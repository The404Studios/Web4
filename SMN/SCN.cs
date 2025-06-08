using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Net.Sockets;
using System.IO;

/// <summary>
/// Smart Network Contract definition and negotiation system
/// Handles contract proposal, negotiation, signing, and enforcement
/// </summary>
[Serializable]
public class SmartNetworkContract
{
    [JsonPropertyName("device_id")]
    public string DeviceId { get; set; }

    [JsonPropertyName("allowed_services")]
    public List<string> AllowedServices { get; set; } = new();

    [JsonPropertyName("bandwidth_limit_kbps")]
    public int BandwidthLimitKbps { get; set; }

    [JsonPropertyName("duration_minutes")]
    public int DurationMinutes { get; set; }

    [JsonPropertyName("encryption")]
    public string Encryption { get; set; } = "AES-256";

    [JsonPropertyName("contract_version")]
    public string ContractVersion { get; set; } = "1.0";

    [JsonPropertyName("created_timestamp")]
    public DateTime CreatedTimestamp { get; set; } = DateTime.UtcNow;

    [JsonPropertyName("expires_timestamp")]
    public DateTime ExpiresTimestamp => CreatedTimestamp.AddMinutes(DurationMinutes);

    [JsonPropertyName("client_signature")]
    public string ClientSignature { get; set; }

    [JsonPropertyName("server_signature")]
    public string ServerSignature { get; set; }

    [JsonPropertyName("allowed_destinations")]
    public List<string> AllowedDestinations { get; set; } = new();

    [JsonPropertyName("max_concurrent_connections")]
    public int MaxConcurrentConnections { get; set; } = 10;

    [JsonPropertyName("data_transfer_limit_mb")]
    public int DataTransferLimitMB { get; set; } = -1; // -1 = unlimited

    public bool IsExpired => DateTime.UtcNow > ExpiresTimestamp;
    
    public bool IsServiceAllowed(string service)
    {
        return AllowedServices.Contains("*") || AllowedServices.Contains(service.ToLower());
    }

    public bool IsDestinationAllowed(string destination)
    {
        if (AllowedDestinations.Contains("*")) return true;
        
        foreach (var allowed in AllowedDestinations)
        {
            if (destination.Contains(allowed, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    public string ToJson()
    {
        var options = new JsonSerializerOptions { WriteIndented = true };
        return JsonSerializer.Serialize(this, options);
    }

    public static SmartNetworkContract FromJson(string json)
    {
        return JsonSerializer.Deserialize<SmartNetworkContract>(json);
    }

    /// <summary>
    /// Create a hash of the contract for signing
    /// </summary>
    public string GetContractHash()
    {
        var contractData = new
        {
            DeviceId,
            AllowedServices,
            BandwidthLimitKbps,
            DurationMinutes,
            Encryption,
            CreatedTimestamp,
            AllowedDestinations,
            MaxConcurrentConnections,
            DataTransferLimitMB
        };

        var json = JsonSerializer.Serialize(contractData);
        using var sha256 = SHA256.Create();
        var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(json));
        return Convert.ToBase64String(hashBytes);
    }
}

public enum ContractNegotiationStatus
{
    Proposed,
    Modified,
    Accepted,
    Rejected,
    Signed,
    Active,
    Expired,
    Terminated
}

public class ContractNegotiationMessage
{
    [JsonPropertyName("message_type")]
    public string MessageType { get; set; } // "PROPOSE", "MODIFY", "ACCEPT", "REJECT", "SIGN"

    [JsonPropertyName("contract")]
    public SmartNetworkContract Contract { get; set; }

    [JsonPropertyName("status")]
    public ContractNegotiationStatus Status { get; set; }

    [JsonPropertyName("reason")]
    public string Reason { get; set; }

    [JsonPropertyName("timestamp")]
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    public string ToJson()
    {
        var options = new JsonSerializerOptions { WriteIndented = true };
        return JsonSerializer.Serialize(this, options);
    }

    public static ContractNegotiationMessage FromJson(string json)
    {
        return JsonSerializer.Deserialize<ContractNegotiationMessage>(json);
    }
}

/// <summary>
/// Handles the contract negotiation handshake between client and server
/// </summary>
public class ContractNegotiationEngine
{
    private readonly string _deviceId;
    private readonly Dictionary<string, SmartNetworkContract> _activeContracts;

    public ContractNegotiationEngine(string deviceId)
    {
        _deviceId = deviceId;
        _activeContracts = new Dictionary<string, SmartNetworkContract>();
    }

    /// <summary>
    /// Client: Create initial contract proposal
    /// </summary>
    public SmartNetworkContract CreateProposal(
        List<string> requestedServices,
        int requestedBandwidthKbps,
        int requestedDurationMinutes,
        List<string> requestedDestinations = null)
    {
        return new SmartNetworkContract
        {
            DeviceId = _deviceId,
            AllowedServices = requestedServices ?? new List<string> { "http", "https", "dns" },
            BandwidthLimitKbps = requestedBandwidthKbps,
            DurationMinutes = requestedDurationMinutes,
            AllowedDestinations = requestedDestinations ?? new List<string> { "*" },
            ContractVersion = "1.0"
        };
    }

    /// <summary>
    /// Server: Review and potentially modify contract proposal
    /// </summary>
    public (SmartNetworkContract modifiedContract, ContractNegotiationStatus status, string reason) 
        ReviewProposal(SmartNetworkContract proposal)
    {
        // Server policy enforcement
        var maxAllowedBandwidth = 1000; // 1 Mbps max
        var maxAllowedDuration = 120;   // 2 hours max
        var allowedServices = new[] { "http", "https", "dns", "ssh" };

        var modified = new SmartNetworkContract
        {
            DeviceId = proposal.DeviceId,
            AllowedServices = proposal.AllowedServices.Where(s => allowedServices.Contains(s)).ToList(),
            BandwidthLimitKbps = Math.Min(proposal.BandwidthLimitKbps, maxAllowedBandwidth),
            DurationMinutes = Math.Min(proposal.DurationMinutes, maxAllowedDuration),
            Encryption = proposal.Encryption,
            AllowedDestinations = proposal.AllowedDestinations,
            MaxConcurrentConnections = Math.Min(proposal.MaxConcurrentConnections, 5),
            DataTransferLimitMB = proposal.DataTransferLimitMB > 0 ? 
                Math.Min(proposal.DataTransferLimitMB, 1000) : 1000 // 1GB max
        };

        // Check if we had to modify anything
        var isModified = modified.BandwidthLimitKbps != proposal.BandwidthLimitKbps ||
                        modified.DurationMinutes != proposal.DurationMinutes ||
                        modified.AllowedServices.Count != proposal.AllowedServices.Count ||
                        modified.MaxConcurrentConnections != proposal.MaxConcurrentConnections;

        if (isModified)
        {
            return (modified, ContractNegotiationStatus.Modified, 
                   "Contract modified to comply with server policies");
        }

        return (modified, ContractNegotiationStatus.Accepted, "Contract accepted as proposed");
    }

    /// <summary>
    /// Sign contract with simple digital signature (for demo - use proper crypto in production)
    /// </summary>
    public string SignContract(SmartNetworkContract contract, string privateKey = null)
    {
        var contractHash = contract.GetContractHash();
        
        // Simple signing for demo (use RSA/ECDSA in production)
        var signature = $"{_deviceId}:{contractHash}:{DateTime.UtcNow:O}";
        using var sha256 = SHA256.Create();
        var signatureBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(signature));
        return Convert.ToBase64String(signatureBytes);
    }

    /// <summary>
    /// Verify contract signature
    /// </summary>
    public bool VerifySignature(SmartNetworkContract contract, string signature, string deviceId)
    {
        // Simple verification for demo
        var contractHash = contract.GetContractHash();
        var expectedSignatureData = $"{deviceId}:{contractHash}:";
        
        try
        {
            var signatureBytes = Convert.FromBase64String(signature);
            // In production, verify with public key cryptography
            return signatureBytes.Length == 32; // SHA256 hash length
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Complete contract negotiation handshake
    /// </summary>
    public async Task<SmartNetworkContract> NegotiateContractAsync(
        NetworkStream stream, 
        SmartNetworkContract initialProposal, 
        bool isServer)
    {
        var reader = new StreamReader(stream);
        var writer = new StreamWriter(stream) { AutoFlush = true };

        try
        {
            if (isServer)
            {
                // Server side: wait for proposal
                var proposalJson = await reader.ReadLineAsync();
                var proposalMessage = ContractNegotiationMessage.FromJson(proposalJson);
                
                if (proposalMessage.MessageType != "PROPOSE")
                    throw new InvalidOperationException("Expected contract proposal");

                // Review and potentially modify
                var (modifiedContract, status, reason) = ReviewProposal(proposalMessage.Contract);

                // Send response
                var response = new ContractNegotiationMessage
                {
                    MessageType = status == ContractNegotiationStatus.Accepted ? "ACCEPT" : "MODIFY",
                    Contract = modifiedContract,
                    Status = status,
                    Reason = reason
                };

                await writer.WriteLineAsync(response.ToJson());

                if (status == ContractNegotiationStatus.Accepted)
                {
                    // Wait for client signature
                    var signatureJson = await reader.ReadLineAsync();
                    var signatureMessage = ContractNegotiationMessage.FromJson(signatureJson);
                    
                    if (signatureMessage.MessageType == "SIGN")
                    {
                        // Add server signature
                        modifiedContract.ClientSignature = signatureMessage.Contract.ClientSignature;
                        modifiedContract.ServerSignature = SignContract(modifiedContract);
                        
                        _activeContracts[modifiedContract.DeviceId] = modifiedContract;
                        
                        Console.WriteLine($"Contract signed and activated for device {modifiedContract.DeviceId}");
                        return modifiedContract;
                    }
                }
            }
            else
            {
                // Client side: send proposal
                var proposalMessage = new ContractNegotiationMessage
                {
                    MessageType = "PROPOSE",
                    Contract = initialProposal,
                    Status = ContractNegotiationStatus.Proposed
                };

                await writer.WriteLineAsync(proposalMessage.ToJson());

                // Wait for server response
                var responseJson = await reader.ReadLineAsync();
                var response = ContractNegotiationMessage.FromJson(responseJson);

                if (response.Status == ContractNegotiationStatus.Accepted || 
                    response.Status == ContractNegotiationStatus.Modified)
                {
                    // Sign the final contract
                    response.Contract.ClientSignature = SignContract(response.Contract);
                    
                    var signatureMessage = new ContractNegotiationMessage
                    {
                        MessageType = "SIGN",
                        Contract = response.Contract,
                        Status = ContractNegotiationStatus.Signed
                    };

                    await writer.WriteLineAsync(signatureMessage.ToJson());
                    
                    _activeContracts[response.Contract.DeviceId] = response.Contract;
                    
                    Console.WriteLine($"Contract negotiated successfully. Final terms: {response.Contract.ToJson()}");
                    return response.Contract;
                }
                else
                {
                    throw new InvalidOperationException($"Contract rejected: {response.Reason}");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Contract negotiation failed: {ex.Message}");
            throw;
        }

        return null;
    }

    public SmartNetworkContract GetActiveContract(string deviceId)
    {
        _activeContracts.TryGetValue(deviceId, out var contract);
        return contract?.IsExpired == false ? contract : null;
    }

    public void TerminateContract(string deviceId)
    {
        _activeContracts.Remove(deviceId);
        Console.WriteLine($"Contract terminated for device {deviceId}");
    }
}

/// <summary>
/// Example usage of the contract negotiation system
/// </summary>
public class ContractNegotiationExample
{
    public static async Task RunClientServerExample()
    {
        // Simulate client and server negotiation engines
        var clientEngine = new ContractNegotiationEngine("client-device-001");
        var serverEngine = new ContractNegotiationEngine("server-gateway-001");

        // Client creates initial proposal
        var proposal = clientEngine.CreateProposal(
            requestedServices: new List<string> { "http", "https", "dns", "ssh" },
            requestedBandwidthKbps: 2000, // 2 Mbps
            requestedDurationMinutes: 180, // 3 hours
            requestedDestinations: new List<string> { "*" }
        );

        Console.WriteLine("=== Smart Network Contract Negotiation Demo ===");
        Console.WriteLine($"Initial proposal:\n{proposal.ToJson()}\n");

        // Server reviews proposal
        var (modifiedContract, status, reason) = serverEngine.ReviewProposal(proposal);
        
        Console.WriteLine($"Server review result: {status}");
        Console.WriteLine($"Reason: {reason}");
        Console.WriteLine($"Final contract terms:\n{modifiedContract.ToJson()}\n");

        // Sign the contract
        modifiedContract.ClientSignature = clientEngine.SignContract(modifiedContract);
        modifiedContract.ServerSignature = serverEngine.SignContract(modifiedContract);

        Console.WriteLine("Contract successfully signed!");
        Console.WriteLine($"Client signature: {modifiedContract.ClientSignature[..20]}...");
        Console.WriteLine($"Server signature: {modifiedContract.ServerSignature[..20]}...");
        
        // Test contract enforcement
        Console.WriteLine("\n=== Testing Contract Enforcement ===");
        Console.WriteLine($"Is 'http' service allowed? {modifiedContract.IsServiceAllowed("http")}");
        Console.WriteLine($"Is 'ftp' service allowed? {modifiedContract.IsServiceAllowed("ftp")}");
        Console.WriteLine($"Is 'google.com' destination allowed? {modifiedContract.IsDestinationAllowed("google.com")}");
        Console.WriteLine($"Contract expires at: {modifiedContract.ExpiresTimestamp}");
        Console.WriteLine($"Is contract expired? {modifiedContract.IsExpired}");
    }
}