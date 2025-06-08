using System;
using System.Threading;
using System.Threading.Tasks;

/// <summary>
/// Token Bucket implementation for bandwidth limiting and QoS
/// Allows bursts but enforces overall rate limits per Smart Network Contract
/// </summary>
public class TokenBucketBandwidthLimiter
{
    private readonly object _lock = new object();
    private double _tokens;
    private readonly double _maxTokens;
    private readonly double _refillRate; // tokens per second
    private DateTime _lastRefill;

    public TokenBucketBandwidthLimiter(double maxBandwidthKbps)
    {
        _maxTokens = maxBandwidthKbps * 1024; // Convert to bytes per second
        _refillRate = _maxTokens; // Refill at max rate
        _tokens = _maxTokens; // Start with full bucket
        _lastRefill = DateTime.UtcNow;
    }

    /// <summary>
    /// Try to consume tokens for packet transmission
    /// Returns true if packet can be sent, false if rate limited
    /// </summary>
    public bool TryConsume(int packetSizeBytes)
    {
        lock (_lock)
        {
            RefillTokens();
            
            if (_tokens >= packetSizeBytes)
            {
                _tokens -= packetSizeBytes;
                return true;
            }
            
            return false; // Rate limited
        }
    }

    /// <summary>
    /// Get delay needed before packet can be sent (for smooth shaping)
    /// </summary>
    public TimeSpan GetDelayForPacket(int packetSizeBytes)
    {
        lock (_lock)
        {
            RefillTokens();
            
            if (_tokens >= packetSizeBytes)
                return TimeSpan.Zero;
            
            double tokensNeeded = packetSizeBytes - _tokens;
            double delaySeconds = tokensNeeded / _refillRate;
            return TimeSpan.FromSeconds(Math.Max(0, delaySeconds));
        }
    }

    private void RefillTokens()
    {
        var now = DateTime.UtcNow;
        var elapsed = (now - _lastRefill).TotalSeconds;
        
        if (elapsed > 0)
        {
            double tokensToAdd = elapsed * _refillRate;
            _tokens = Math.Min(_maxTokens, _tokens + tokensToAdd);
            _lastRefill = now;
        }
    }

    public double CurrentTokens => _tokens;
    public double MaxTokens => _maxTokens;
}

/// <summary>
/// Quality of Service packet prioritizer
/// Implements simple priority queue for different packet types
/// </summary>
public enum PacketPriority
{
    Control = 0,    // Highest priority (contract negotiation, control messages)
    DNS = 1,        // High priority (DNS queries)
    Interactive = 2, // Medium priority (SSH, small HTTP requests)
    Bulk = 3        // Low priority (file transfers, large downloads)
}

public class QoSPacket
{
    public byte[] Data { get; set; }
    public PacketPriority Priority { get; set; }
    public DateTime Timestamp { get; set; }
    public string DestinationEndpoint { get; set; }
}

public class QoSPacketScheduler
{
    private readonly TokenBucketBandwidthLimiter _bandwidthLimiter;
    private readonly SortedDictionary<PacketPriority, Queue<QoSPacket>> _priorityQueues;
    private readonly object _queueLock = new object();

    public QoSPacketScheduler(double maxBandwidthKbps)
    {
        _bandwidthLimiter = new TokenBucketBandwidthLimiter(maxBandwidthKbps);
        _priorityQueues = new SortedDictionary<PacketPriority, Queue<QoSPacket>>();
        
        // Initialize priority queues
        foreach (PacketPriority priority in Enum.GetValues<PacketPriority>())
        {
            _priorityQueues[priority] = new Queue<QoSPacket>();
        }
    }

    public void EnqueuePacket(QoSPacket packet)
    {
        lock (_queueLock)
        {
            _priorityQueues[packet.Priority].Enqueue(packet);
        }
    }

    /// <summary>
    /// Dequeue next packet respecting both priority and bandwidth limits
    /// </summary>
    public async Task<QoSPacket> DequeuePacketAsync(CancellationToken cancellationToken = default)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            QoSPacket packet = null;
            
            lock (_queueLock)
            {
                // Try to get highest priority packet
                foreach (var priorityQueue in _priorityQueues)
                {
                    if (priorityQueue.Value.Count > 0)
                    {
                        packet = priorityQueue.Value.Dequeue();
                        break;
                    }
                }
            }

            if (packet == null)
            {
                await Task.Delay(10, cancellationToken); // Wait for packets
                continue;
            }

            // Check bandwidth limits
            var delay = _bandwidthLimiter.GetDelayForPacket(packet.Data.Length);
            if (delay > TimeSpan.Zero)
            {
                await Task.Delay(delay, cancellationToken);
            }

            if (_bandwidthLimiter.TryConsume(packet.Data.Length))
            {
                return packet;
            }

            // If we can't send now, put it back and wait
            lock (_queueLock)
            {
                // Put back at front of queue
                var queue = _priorityQueues[packet.Priority];
                var tempList = queue.ToList();
                queue.Clear();
                queue.Enqueue(packet);
                foreach (var p in tempList)
                    queue.Enqueue(p);
            }

            await Task.Delay(10, cancellationToken);
        }

        return null;
    }

    public int GetQueueLength(PacketPriority priority)
    {
        lock (_queueLock)
        {
            return _priorityQueues[priority].Count;
        }
    }
}

/// <summary>
/// Example usage showing bandwidth limiting and QoS in action
/// </summary>
public class BandwidthLimiterExample
{
    public static async Task RunExample()
    {
        // Create QoS scheduler with 500 Kbps limit (as per Smart Contract example)
        var scheduler = new QoSPacketScheduler(500);

        // Simulate different types of packets
        var controlPacket = new QoSPacket
        {
            Data = new byte[64], // Small control message
            Priority = PacketPriority.Control,
            Timestamp = DateTime.UtcNow,
            DestinationEndpoint = "control.mesh.local"
        };

        var bulkPacket = new QoSPacket
        {
            Data = new byte[1024 * 50], // 50KB bulk transfer
            Priority = PacketPriority.Bulk,
            Timestamp = DateTime.UtcNow,
            DestinationEndpoint = "file.server.com"
        };

        // Enqueue packets
        scheduler.EnqueuePacket(controlPacket);
        scheduler.EnqueuePacket(bulkPacket);

        Console.WriteLine("Starting QoS packet scheduling...");

        // Process packets with QoS and bandwidth limiting
        var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        
        while (!cts.Token.IsCancellationRequested)
        {
            var packet = await scheduler.DequeuePacketAsync(cts.Token);
            if (packet != null)
            {
                Console.WriteLine($"Sent {packet.Priority} packet ({packet.Data.Length} bytes) to {packet.DestinationEndpoint}");
            }
        }
    }
}