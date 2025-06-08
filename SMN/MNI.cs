using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Buffers;

/// <summary>
/// Persistent state manager for contracts and token buckets
/// Addresses the "reboot bypass" vulnerability by persisting limits across restarts
/// </summary>
public class MeshNodeState
{
    [JsonPropertyName("active_contracts")]
    public Dictionary<string, HardenedSmartContract> ActiveContracts { get; set; } = new();

    [JsonPropertyName("token_bucket_states")]
    public Dictionary<string, TokenBucketState> TokenBucketStates { get; set; } = new();

    [JsonPropertyName("last_saved")]
    public DateTime LastSaved { get; set; }

    [JsonPropertyName("node_id")]
    public string NodeId { get; set; }

    [JsonPropertyName("startup_time")]
    public DateTime StartupTime { get; set; }
}

public class TokenBucketState
{
    [JsonPropertyName("device_id")]
    public string DeviceId { get; set; }

    [JsonPropertyName("remaining_tokens")]
    public double RemainingTokens { get; set; }

    [JsonPropertyName("last_refill")]
    public DateTime LastRefill { get; set; }

    [JsonPropertyName("max_tokens")]
    public double MaxTokens { get; set; }

    [JsonPropertyName("refill_rate")]
    public double RefillRate { get; set; }
}

/// <summary>
/// Thread-safe state persistence manager
/// </summary>
public class StatePersistenceManager
{
    private readonly string _statePath;
    private readonly Timer _saveTimer;
    private readonly object _stateLock = new object();
    private MeshNodeState _currentState;
    private bool _isDirty = false;

    public StatePersistenceManager(string nodeId, string stateDirectory = null)
    {
        var stateDir = stateDirectory ?? 
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), 
                        "MeshNetwork", "state");
        
        Directory.CreateDirectory(stateDir);
        _statePath = Path.Combine(stateDir, $"{nodeId}_state.json");
        
        // Auto-save every 30 seconds if dirty
        _saveTimer = new Timer(AutoSave, null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
        
        LoadState(nodeId);
    }

    private void LoadState(string nodeId)
    {
        lock (_stateLock)
        {
            try
            {
                if (File.Exists(_statePath))
                {
                    var json = File.ReadAllText(_statePath);
                    _currentState = JsonSerializer.Deserialize<MeshNodeState>(json) ?? new MeshNodeState();
                    Console.WriteLine($"Loaded state: {_currentState.ActiveContracts.Count} contracts, {_currentState.TokenBucketStates.Count} token buckets");
                }
                else
                {
                    _currentState = new MeshNodeState();
                }

                _currentState.NodeId = nodeId;
                _currentState.StartupTime = DateTime.UtcNow;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to load state: {ex.Message}. Starting fresh.");
                _currentState = new MeshNodeState { NodeId = nodeId, StartupTime = DateTime.UtcNow };
            }
        }
    }

    public void SaveContract(HardenedSmartContract contract)
    {
        lock (_stateLock)
        {
            _currentState.ActiveContracts[contract.DeviceId] = contract;
            _isDirty = true;
        }
    }

    public void RemoveContract(string deviceId)
    {
        lock (_stateLock)
        {
            _currentState.ActiveContracts.Remove(deviceId);
            _currentState.TokenBucketStates.Remove(deviceId);
            _isDirty = true;
        }
    }

    public void SaveTokenBucketState(string deviceId, TokenBucketBandwidthLimiter limiter)
    {
        lock (_stateLock)
        {
            _currentState.TokenBucketStates[deviceId] = new TokenBucketState
            {
                DeviceId = deviceId,
                RemainingTokens = limiter.CurrentTokens,
                LastRefill = DateTime.UtcNow,
                MaxTokens = limiter.MaxTokens,
                RefillRate = limiter.MaxTokens // Assuming refill rate == max tokens
            };
            _isDirty = true;
        }
    }

    public TokenBucketState GetTokenBucketState(string deviceId)
    {
        lock (_stateLock)
        {
            _currentState.TokenBucketStates.TryGetValue(deviceId, out var state);
            return state;
        }
    }

    public Dictionary<string, HardenedSmartContract> GetActiveContracts()
    {
        lock (_stateLock)
        {
            return new Dictionary<string, HardenedSmartContract>(_currentState.ActiveContracts);
        }
    }

    public void SaveNow()
    {
        lock (_stateLock)
        {
            try
            {
                _currentState.LastSaved = DateTime.UtcNow;
                var json = JsonSerializer.Serialize(_currentState, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(_statePath, json);
                _isDirty = false;
                Console.WriteLine($"State saved: {_currentState.ActiveContracts.Count} contracts");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to save state: {ex.Message}");
            }
        }
    }

    private void AutoSave(object state)
    {
        if (_isDirty)
        {
            SaveNow();
        }
    }

    public void Dispose()
    {
        _saveTimer?.Dispose();
        SaveNow(); // Final save on shutdown
    }
}

/// <summary>
/// Performance-optimized token bucket with persistence
/// </summary>
public class PersistentTokenBucketLimiter : TokenBucketBandwidthLimiter
{
    private readonly string _deviceId;
    private readonly StatePersistenceManager _persistenceManager;

    public PersistentTokenBucketLimiter(string deviceId, double maxBandwidthKbps, 
                                       StatePersistenceManager persistenceManager) 
        : base(maxBandwidthKbps)
    {
        _deviceId = deviceId;
        _persistenceManager = persistenceManager;
        
        // Restore previous state if available
        var previousState = persistenceManager.GetTokenBucketState(deviceId);
        if (previousState != null)
        {
            RestoreState(previousState);
            Console.WriteLine($"Restored token bucket for {deviceId}: {CurrentTokens:F0} tokens");
        }
    }

    private void RestoreState(TokenBucketState state)
    {
        var elapsed = (DateTime.UtcNow - state.LastRefill).TotalSeconds;
        var tokensToAdd = elapsed * state.RefillRate;
        var restoredTokens = Math.Min(state.MaxTokens, state.RemainingTokens + tokensToAdd);
        
        // Use reflection to set private _tokens field
        var tokensField = typeof(TokenBucketBandwidthLimiter).GetField("_tokens", 
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        tokensField?.SetValue(this, restoredTokens);
    }

    public override bool TryConsume(int packetSizeBytes)
    {
        var result = base.TryConsume(packetSizeBytes);
        
        // Periodically save state (not every packet for performance)
        if (Environment.TickCount % 1000 == 0) // Every ~1000 packets
        {
            _persistenceManager.SaveTokenBucketState(_deviceId, this);
        }
        
        return result;
    }
}

/// <summary>
/// Observability and metrics for the mesh node
/// </summary>
public class MeshNodeMetrics
{
    public long PacketsForwarded { get; set; }
    public long PacketsDropped { get; set; }
    public long BytesTransferred { get; set; }
    public long RateLimitEvents { get; set; }
    public DateTime StartTime { get; set; } = DateTime.UtcNow;
    public TimeSpan Uptime => DateTime.UtcNow - StartTime;
    public Dictionary<string, long> DropReasons { get; set; } = new();

    public void RecordPacketDropped(string reason)
    {
        Interlocked.Increment(ref PacketsDropped);
        DropReasons.TryGetValue(reason, out var count);
        DropReasons[reason] = count + 1;
    }

    public void RecordRateLimit(TimeSpan delay)
    {
        Interlocked.Increment(ref RateLimitEvents);
    }

    public void RecordPacketForwarded(int size)
    {
        Interlocked.Increment(ref PacketsForwarded);
        Interlocked.Add(ref BytesTransferred, size);
    }

    public void PrintStats()
    {
        Console.WriteLine($"=== Mesh Node Statistics (Uptime: {Uptime:dd\\.hh\\:mm\\:ss}) ===");
        Console.WriteLine($"Packets Forwarded: {PacketsForwarded:N0}");
        Console.WriteLine($"Packets Dropped: {PacketsDropped:N0}");
        Console.WriteLine($"Bytes Transferred: {BytesTransferred:N0}");
        Console.WriteLine($"Rate Limit Events: {RateLimitEvents:N0}");
        
        if (DropReasons.Any())
        {
            Console.WriteLine("Drop Reasons:");
            foreach (var kvp in DropReasons.OrderByDescending(x => x.Value))
            {
                Console.WriteLine($"  {kvp.Key}: {kvp.Value:N0}");
            }
        }
    }
}

/// <summary>
/// Main mesh node integration class that ties all components together
/// Addresses lifecycle management, persistence, and performance concerns
/// </summary>
public class MeshNode : IDisposable
{
    private readonly string _nodeId;
    private readonly MeshNodeConfiguration _config;
    
    // Core components
    private HardenedContractEngine _contractEngine;
    private ITunTapInterface _tunTapInterface;
    private P2PConnectionCoordinator _p2pCoordinator;
    private StatePersistenceManager _persistenceManager;
    
    // Per-peer resources
    private readonly ConcurrentDictionary<string, PersistentTokenBucketLimiter> _peerLimiters;
    private readonly ConcurrentDictionary<string, QoSPacketScheduler> _peerSchedulers;
    
    // Lifecycle management
    private readonly CancellationTokenSource _shutdownCts;
    private readonly List<Task> _backgroundTasks;
    
    // Observability
    private readonly MeshNodeMetrics _metrics;
    private readonly Timer _metricsTimer;

    // Performance optimizations
    private readonly ArrayPool<byte> _packetBufferPool;

    public event Action<string> OnPacketDropped;
    public event Action<TimeSpan> OnRateLimited;

    public MeshNode(string nodeId, MeshNodeConfiguration config = null)
    {
        _nodeId = nodeId ?? $"mesh-{Environment.MachineName}-{Environment.ProcessId}";
        _config = config ?? new MeshNodeConfiguration();
        
        _peerLimiters = new ConcurrentDictionary<string, PersistentTokenBucketLimiter>();
        _peerSchedulers = new ConcurrentDictionary<string, QoSPacketScheduler>();
        _shutdownCts = new CancellationTokenSource();
        _backgroundTasks = new List<Task>();
        _metrics = new MeshNodeMetrics();
        _packetBufferPool = ArrayPool<byte>.Shared;
        
        // Metrics reporting timer
        _metricsTimer = new Timer(_ => _metrics.PrintStats(), null, 
                                TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(5));
        
        Console.WriteLine($"MeshNode {_nodeId} initialized");
    }

    public async Task<bool> StartAsync()
    {
        try
        {
            Console.WriteLine($"Starting MeshNode {_nodeId}...");

            // Initialize persistence manager
            _persistenceManager = new StatePersistenceManager(_nodeId, _config.StateDirectory);

            // Initialize contract engine with secure keystore
            var keystore = new SecureKeystore(_config.KeystoreDirectory);
            _contractEngine = new HardenedContractEngine(_nodeId, keystore);

            // Restore active contracts from persistence
            var savedContracts = _persistenceManager.GetActiveContracts();
            foreach (var kvp in savedContracts)
            {
                if (!kvp.Value.IsExpired)
                {
                    _contractEngine.StoreActiveContract(kvp.Value);
                    await SetupPeerResourcesAsync(kvp.Value);
                    Console.WriteLine($"Restored active contract for {kvp.Key}");
                }
                else
                {
                    _persistenceManager.RemoveContract(kvp.Key);
                    Console.WriteLine($"Removed expired contract for {kvp.Key}");
                }
            }

            // Initialize TUN/TAP interface if requested
            if (_config.EnableVPN)
            {
                var mode = _config.VPNMode;
                _tunTapInterface = TunTapFactory.CreateInterface(mode, $"mesh{_nodeId[..8]}");
                
                if (_tunTapInterface is WindowsTapInterface tapInterface)
                {
                    await tapInterface.ConnectAsync();
                }
                else if (_tunTapInterface is LinuxTunInterface tunInterface)
                {
                    await tunInterface.ConnectAsync();
                }

                // Start packet forwarding task
                _backgroundTasks.Add(Task.Run(PacketForwardingLoop, _shutdownCts.Token));
                Console.WriteLine($"VPN interface {_tunTapInterface.InterfaceName} started");
            }

            // Initialize P2P coordinator
            _p2pCoordinator = new P2PConnectionCoordinator(_nodeId, _config.P2PPort);
            var p2pInitialized = await _p2pCoordinator.InitializeAsync();
            
            if (p2pInitialized)
            {
                _p2pCoordinator.DataReceived += OnP2PDataReceived;
                _p2pCoordinator.PeerConnected += OnPeerConnected;
                _p2pCoordinator.PeerDisconnected += OnPeerDisconnected;
                
                await _p2pCoordinator.StartHeartbeatAsync(_config.HeartbeatIntervalSeconds);
                Console.WriteLine("P2P coordinator started");
            }

            // Start background maintenance tasks
            _backgroundTasks.Add(Task.Run(ContractExpirationMonitor, _shutdownCts.Token));
            _backgroundTasks.Add(Task.Run(StatePersistenceLoop, _shutdownCts.Token));

            Console.WriteLine($"MeshNode {_nodeId} started successfully");
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to start MeshNode {_nodeId}: {ex.Message}");
            return false;
        }
    }

    public async Task StopAsync()
    {
        Console.WriteLine($"Stopping MeshNode {_nodeId}...");

        // Signal shutdown
        _shutdownCts.Cancel();

        // Wait for background tasks to complete
        try
        {
            await Task.WhenAll(_backgroundTasks.ToArray()).WaitAsync(TimeSpan.FromSeconds(10));
        }
        catch (TimeoutException)
        {
            Console.WriteLine("Background tasks did not complete in time");
        }

        // Clean shutdown of components
        _p2pCoordinator?.Dispose();
        _tunTapInterface?.Dispose();
        _persistenceManager?.Dispose();
        _metricsTimer?.Dispose();

        Console.WriteLine($"MeshNode {_nodeId} stopped");
    }

    /// <summary>
    /// Accept a new peer contract and set up resources
    /// </summary>
    public async Task<bool> AcceptPeerContractAsync(HardenedSmartContract proposedContract)
    {
        try
        {
            // Review and validate the contract
            var (modifiedContract, accepted, reason) = _contractEngine.ReviewAndValidateProposal(proposedContract);
            
            if (!accepted)
            {
                Console.WriteLine($"Contract rejected for {proposedContract.DeviceId}: {reason}");
                return false;
            }

            // Sign and store the contract
            modifiedContract.ServerSignature = _contractEngine.SignContract(modifiedContract);
            _contractEngine.StoreActiveContract(modifiedContract);
            _persistenceManager.SaveContract(modifiedContract);

            // Set up peer-specific resources
            await SetupPeerResourcesAsync(modifiedContract);

            Console.WriteLine($"Contract accepted for {modifiedContract.DeviceId} - {reason}");
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to accept contract for {proposedContract.DeviceId}: {ex.Message}");
            return false;
        }
    }

    private async Task SetupPeerResourcesAsync(HardenedSmartContract contract)
    {
        var deviceId = contract.DeviceId;

        // Create persistent token bucket limiter
        var limiter = new PersistentTokenBucketLimiter(deviceId, contract.BandwidthLimitKbps, _persistenceManager);
        _peerLimiters[deviceId] = limiter;

        // Create QoS scheduler
        var scheduler = new QoSPacketScheduler(contract.BandwidthLimitKbps);
        _peerSchedulers[deviceId] = scheduler;

        Console.WriteLine($"Set up resources for peer {deviceId}: {contract.BandwidthLimitKbps} Kbps limit");
    }

    /// <summary>
    /// Main packet forwarding loop for VPN functionality
    /// </summary>
    private async Task PacketForwardingLoop()
    {
        Console.WriteLine("Packet forwarding loop started");
        
        while (!_shutdownCts.Token.IsCancellationRequested)
        {
            try
            {
                var packet = await _tunTapInterface.ReadPacketAsync(_shutdownCts.Token);
                if (packet != null)
                {
                    await ProcessIncomingPacket(packet);
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Packet forwarding error: {ex.Message}");
                await Task.Delay(100, _shutdownCts.Token);
            }
        }
        
        Console.WriteLine("Packet forwarding loop stopped");
    }

    private async Task ProcessIncomingPacket(byte[] packet)
    {
        // Parse packet to determine destination and enforcement
        var parsed = _config.VPNMode == TunTapMode.TAP
            ? PacketParser.ParseEthernetFrame(packet)
            : PacketParser.ParseIPPacket(packet);

        if (!parsed.IsValid)
        {
            _metrics.RecordPacketDropped("invalid_packet");
            OnPacketDropped?.Invoke("invalid_packet");
            return;
        }

        // Find appropriate peer contract (simplified - in reality this would be more complex routing)
        var targetPeer = FindTargetPeerForDestination(parsed.DestinationIP?.ToString());
        if (targetPeer == null)
        {
            _metrics.RecordPacketDropped("no_route");
            OnPacketDropped?.Invoke("no_route");
            return;
        }

        var contract = _contractEngine.GetActiveContract(targetPeer);
        if (contract == null)
        {
            _metrics.RecordPacketDropped("no_contract");
            OnPacketDropped?.Invoke("no_contract");
            return;
        }

        // Enforce contract terms
        if (!EnforceContractTerms(contract, parsed))
        {
            _metrics.RecordPacketDropped("contract_violation");
            OnPacketDropped?.Invoke("contract_violation");
            return;
        }

        // Apply rate limiting
        if (_peerLimiters.TryGetValue(targetPeer, out var limiter))
        {
            var delay = limiter.GetDelayForPacket(packet.Length);
            if (delay > TimeSpan.Zero)
            {
                _metrics.RecordRateLimit(delay);
                OnRateLimited?.Invoke(delay);
                await Task.Delay(delay, _shutdownCts.Token);
            }

            if (!limiter.TryConsume(packet.Length))
            {
                _metrics.RecordPacketDropped("rate_limited");
                OnPacketDropped?.Invoke("rate_limited");
                return;
            }
        }

        // Forward packet to peer
        await ForwardPacketToPeer(targetPeer, packet);
        _metrics.RecordPacketForwarded(packet.Length);
    }

    private string FindTargetPeerForDestination(string destination)
    {
        // Simplified routing - in practice this would use routing tables
        var activeContracts = _contractEngine.GetAllActiveContracts();
        return activeContracts.Keys.FirstOrDefault();
    }

    private bool EnforceContractTerms(HardenedSmartContract contract, PacketParser.ParsedPacket packet)
    {
        // Check if protocol is allowed
        var protocol = packet.Protocol?.ToString().ToLower() ?? "unknown";
        if (!contract.IsServiceAllowed(protocol))
        {
            return false;
        }

        // Check if destination is allowed
        var destination = packet.DestinationIP?.ToString() ?? "";
        if (!contract.IsDestinationAllowed(destination))
        {
            return false;
        }

        return true;
    }

    private async Task ForwardPacketToPeer(string peerId, byte[] packet)
    {
        try
        {
            await _p2pCoordinator.SendToPeerAsync(peerId, packet);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to forward packet to {peerId}: {ex.Message}");
            _metrics.RecordPacketDropped("forward_failed");
        }
    }

    // Event handlers
    private void OnP2PDataReceived(string fromPeer, byte[] data)
    {
        // Write received packet to TUN/TAP interface
        _ = Task.Run(async () =>
        {
            try
            {
                if (_tunTapInterface != null)
                {
                    await _tunTapInterface.WritePacketAsync(data);
                    _metrics.RecordPacketForwarded(data.Length);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to write packet from {fromPeer}: {ex.Message}");
            }
        });
    }

    private void OnPeerConnected(string peerId)
    {
        Console.WriteLine($"Peer connected: {peerId}");
    }

    private void OnPeerDisconnected(string peerId)
    {
        Console.WriteLine($"Peer disconnected: {peerId}");
        
        // Clean up peer resources
        _peerLimiters.TryRemove(peerId, out _);
        _peerSchedulers.TryRemove(peerId, out _);
    }

    // Background maintenance tasks
    private async Task ContractExpirationMonitor()
    {
        while (!_shutdownCts.Token.IsCancellationRequested)
        {
            try
            {
                var contracts = _contractEngine.GetAllActiveContracts();
                foreach (var kvp in contracts)
                {
                    if (kvp.Value.IsExpired)
                    {
                        Console.WriteLine($"Contract expired for {kvp.Key}");
                        _persistenceManager.RemoveContract(kvp.Key);
                        OnPeerDisconnected(kvp.Key);
                    }
                }

                await Task.Delay(TimeSpan.FromMinutes(1), _shutdownCts.Token);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Contract expiration monitor error: {ex.Message}");
            }
        }
    }

    private async Task StatePersistenceLoop()
    {
        while (!_shutdownCts.Token.IsCancellationRequested)
        {
            try
            {
                // Persist token bucket states
                foreach (var kvp in _peerLimiters)
                {
                    _persistenceManager.SaveTokenBucketState(kvp.Key, kvp.Value);
                }

                await Task.Delay(TimeSpan.FromMinutes(5), _shutdownCts.Token);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"State persistence error: {ex.Message}");
            }
        }
    }

    public void Dispose()
    {
        StopAsync().Wait(TimeSpan.FromSeconds(10));
        _shutdownCts?.Dispose();
    }
}

/// <summary>
/// Configuration class for MeshNode
/// </summary>
public class MeshNodeConfiguration
{
    public bool EnableVPN { get; set; } = true;
    public TunTapMode VPNMode { get; set; } = TunTapMode.TUN;
    public int P2PPort { get; set; } = 0; // 0 = random port
    public int HeartbeatIntervalSeconds { get; set; } = 30;
    public string StateDirectory { get; set; } = null;
    public string KeystoreDirectory { get; set; } = null;
    public int MaxPeers { get; set; } = 100;
    public int PacketBufferSize { get; set; } = 1500;
}

/// <summary>
/// Example usage of the integrated MeshNode
/// </summary>
public class MeshNodeExample
{
    public static async Task RunExample()
    {
        Console.WriteLine("=== Integrated MeshNode Demo ===");

        var config = new MeshNodeConfiguration
        {
            EnableVPN = true,
            VPNMode = TunTapMode.TUN,
            HeartbeatIntervalSeconds = 30
        };

        var meshNode = new MeshNode("example-node-001", config);

        // Set up event handlers
        meshNode.OnPacketDropped += reason => Console.WriteLine($"Packet dropped: {reason}");
        meshNode.OnRateLimited += delay => Console.WriteLine($"Rate limited: {delay.TotalMilliseconds:F0}ms delay");

        try
        {
            var started = await meshNode.StartAsync();
            if (!started)
            {
                Console.WriteLine("Failed to start mesh node");
                return;
            }

            Console.WriteLine("Mesh node running. Press any key to stop...");
            Console.ReadKey();
        }
        finally
        {
            await meshNode.StopAsync();
            meshNode.Dispose();
        }
    }
}
