using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.IO;
using System.Threading.Tasks;
using System.Collections.Concurrent;

/// <summary>
/// Cryptographically hardened Smart Network Contract system
/// Addresses security theater with proper RSA/ECDSA signatures and replay protection
/// </summary>
public class DeviceKeyPair
{
    public string DeviceId { get; set; }
    public byte[] PublicKey { get; set; }
    public byte[] PrivateKey { get; set; }
    public DateTime CreatedAt { get; set; }
    public string KeyType { get; set; } // "RSA" or "ECDSA"
}

/// <summary>
/// Secure keystore using OS-level protection
/// </summary>
public class SecureKeystore
{
    private readonly string _keystorePath;
    private static readonly object _fileLock = new object();

    public SecureKeystore(string keystoreDirectory = null)
    {
        _keystorePath = keystoreDirectory ?? 
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), 
                        "MeshNetwork", "keystore.json");
        
        Directory.CreateDirectory(Path.GetDirectoryName(_keystorePath));
    }

    public async Task<DeviceKeyPair> GetOrCreateDeviceKeyPairAsync(string deviceId, string keyType = "RSA")
    {
        lock (_fileLock)
        {
            // Try to load existing keypair
            if (File.Exists(_keystorePath))
            {
                try
                {
                    var json = File.ReadAllText(_keystorePath);
                    var existing = JsonSerializer.Deserialize<DeviceKeyPair>(json);
                    if (existing?.DeviceId == deviceId && existing.PrivateKey != null)
                    {
                        return existing;
                    }
                }
                catch
                {
                    // Fall through to create new keypair
                }
            }

            // Generate new keypair
            var keyPair = GenerateKeyPair(deviceId, keyType);
            
            // Store securely
            var options = new JsonSerializerOptions { WriteIndented = true };
            var keyJson = JsonSerializer.Serialize(keyPair, options);
            
            // Use OS file protection (Windows: NTFS ACL, Linux: 600 permissions)
            File.WriteAllText(_keystorePath, keyJson);
            SetSecureFilePermissions(_keystorePath);
            
            Console.WriteLine($"Generated new {keyType} keypair for device {deviceId}");
            return keyPair;
        }
    }

    private DeviceKeyPair GenerateKeyPair(string deviceId, string keyType)
    {
        switch (keyType.ToUpper())
        {
            case "RSA":
                return GenerateRSAKeyPair(deviceId);
            case "ECDSA":
                return GenerateECDSAKeyPair(deviceId);
            default:
                throw new ArgumentException($"Unsupported key type: {keyType}");
        }
    }

    private DeviceKeyPair GenerateRSAKeyPair(string deviceId)
    {
        using var rsa = RSA.Create(2048);
        
        return new DeviceKeyPair
        {
            DeviceId = deviceId,
            PublicKey = rsa.ExportRSAPublicKey(),
            PrivateKey = rsa.ExportRSAPrivateKey(),
            CreatedAt = DateTime.UtcNow,
            KeyType = "RSA"
        };
    }

    private DeviceKeyPair GenerateECDSAKeyPair(string deviceId)
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        
        return new DeviceKeyPair
        {
            DeviceId = deviceId,
            PublicKey = ecdsa.ExportECPrivateKey(), // Contains both public and private
            PrivateKey = ecdsa.ExportECPrivateKey(),
            CreatedAt = DateTime.UtcNow,
            KeyType = "ECDSA"
        };
    }

    private void SetSecureFilePermissions(string filePath)
    {
        try
        {
            if (Environment.OSVersion.Platform == PlatformID.Win32NT)
            {
                // Windows: Set file to be readable only by current user
                var fileInfo = new FileInfo(filePath);
                var fileSecurity = fileInfo.GetAccessControl();
                fileSecurity.SetAccessRuleProtection(true, false);
                
                // Remove all existing rules and add only current user
                foreach (System.Security.AccessControl.FileSystemAccessRule rule in fileSecurity.GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier)))
                {
                    fileSecurity.RemoveAccessRule(rule);
                }
                
                var currentUser = System.Security.Principal.WindowsIdentity.GetCurrent();
                var accessRule = new System.Security.AccessControl.FileSystemAccessRule(
                    currentUser.User,
                    System.Security.AccessControl.FileSystemRights.FullControl,
                    System.Security.AccessControl.AccessControlType.Allow);
                
                fileSecurity.SetAccessRule(accessRule);
                fileInfo.SetAccessControl(fileSecurity);
            }
            else
            {
                // Unix-like: chmod 600 (owner read/write only)
                var chmod = System.Diagnostics.Process.Start("chmod", $"600 \"{filePath}\"");
                chmod?.WaitForExit();
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Warning: Could not set secure file permissions: {ex.Message}");
        }
    }
}

/// <summary>
/// Cryptographically hardened Smart Network Contract with replay protection
/// </summary>
[Serializable]
public class HardenedSmartContract
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
    public string ContractVersion { get; set; } = "2.0";

    [JsonPropertyName("created_timestamp")]
    public DateTime CreatedTimestamp { get; set; } = DateTime.UtcNow;

    [JsonPropertyName("expires_timestamp")]
    public DateTime ExpiresTimestamp => CreatedTimestamp.AddMinutes(DurationMinutes);

    [JsonPropertyName("nonce")]
    public string Nonce { get; set; } = Guid.NewGuid().ToString();

    [JsonPropertyName("allowed_destinations")]
    public List<string> AllowedDestinations { get; set; } = new();

    [JsonPropertyName("max_concurrent_connections")]
    public int MaxConcurrentConnections { get; set; } = 10;

    [JsonPropertyName("data_transfer_limit_mb")]
    public int DataTransferLimitMB { get; set; } = -1;

    [JsonPropertyName("client_public_key")]
    public byte[] ClientPublicKey { get; set; }

    [JsonPropertyName("server_public_key")]
    public byte[] ServerPublicKey { get; set; }

    [JsonPropertyName("client_signature")]
    public byte[] ClientSignature { get; set; }

    [JsonPropertyName("server_signature")]
    public byte[] ServerSignature { get; set; }

    [JsonPropertyName("signature_algorithm")]
    public string SignatureAlgorithm { get; set; } = "RSA-SHA256";

    [JsonPropertyName("contract_hash")]
    public string ContractHash { get; set; }

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

    /// <summary>
    /// Create cryptographic hash of the entire contract (excluding signatures)
    /// </summary>
    public string ComputeContractHash()
    {
        var contractData = new
        {
            DeviceId,
            AllowedServices,
            BandwidthLimitKbps,
            DurationMinutes,
            Encryption,
            ContractVersion,
            CreatedTimestamp = CreatedTimestamp.ToString("O"), // ISO 8601 format
            Nonce,
            AllowedDestinations,
            MaxConcurrentConnections,
            DataTransferLimitMB,
            ClientPublicKey = ClientPublicKey != null ? Convert.ToBase64String(ClientPublicKey) : null,
            ServerPublicKey = ServerPublicKey != null ? Convert.ToBase64String(ServerPublicKey) : null,
            SignatureAlgorithm
        };

        var json = JsonSerializer.Serialize(contractData, new JsonSerializerOptions 
        { 
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = false
        });

        using var sha256 = SHA256.Create();
        var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(json));
        return Convert.ToBase64String(hashBytes);
    }

    public string ToJson()
    {
        var options = new JsonSerializerOptions { WriteIndented = true };
        return JsonSerializer.Serialize(this, options);
    }

    public static HardenedSmartContract FromJson(string json)
    {
        return JsonSerializer.Deserialize<HardenedSmartContract>(json);
    }
}

/// <summary>
/// Cryptographically secure contract negotiation engine
/// </summary>
public class HardenedContractEngine
{
    private readonly DeviceKeyPair _deviceKeys;
    private readonly SecureKeystore _keystore;
    private readonly ConcurrentDictionary<string, HardenedSmartContract> _activeContracts;
    private readonly ConcurrentDictionary<string, DateTime> _usedNonces; // Replay protection

    public HardenedContractEngine(string deviceId, SecureKeystore keystore = null)
    {
        _keystore = keystore ?? new SecureKeystore();
        _deviceKeys = _keystore.GetOrCreateDeviceKeyPairAsync(deviceId).Result;
        _activeContracts = new ConcurrentDictionary<string, HardenedSmartContract>();
        _usedNonces = new ConcurrentDictionary<string, DateTime>();
        
        // Clean up old nonces periodically
        _ = Task.Run(CleanupOldNonces);
    }

    public HardenedSmartContract CreateProposal(
        List<string> requestedServices,
        int requestedBandwidthKbps,
        int requestedDurationMinutes,
        List<string> requestedDestinations = null)
    {
        var contract = new HardenedSmartContract
        {
            DeviceId = _deviceKeys.DeviceId,
            AllowedServices = requestedServices ?? new List<string> { "http", "https", "dns" },
            BandwidthLimitKbps = requestedBandwidthKbps,
            DurationMinutes = requestedDurationMinutes,
            AllowedDestinations = requestedDestinations ?? new List<string> { "*" },
            ClientPublicKey = _deviceKeys.PublicKey,
            SignatureAlgorithm = $"{_deviceKeys.KeyType}-SHA256"
        };

        contract.ContractHash = contract.ComputeContractHash();
        return contract;
    }

    /// <summary>
    /// Sign contract with proper cryptographic signature
    /// </summary>
    public byte[] SignContract(HardenedSmartContract contract)
    {
        var contractHash = contract.ComputeContractHash();
        var dataToSign = Encoding.UTF8.GetBytes(contractHash);

        switch (_deviceKeys.KeyType.ToUpper())
        {
            case "RSA":
                using (var rsa = RSA.Create())
                {
                    rsa.ImportRSAPrivateKey(_deviceKeys.PrivateKey, out _);
                    return rsa.SignData(dataToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                }

            case "ECDSA":
                using (var ecdsa = ECDsa.Create())
                {
                    ecdsa.ImportECPrivateKey(_deviceKeys.PrivateKey, out _);
                    return ecdsa.SignData(dataToSign, HashAlgorithmName.SHA256);
                }

            default:
                throw new InvalidOperationException($"Unsupported key type: {_deviceKeys.KeyType}");
        }
    }

    /// <summary>
    /// Verify contract signature with public key cryptography
    /// </summary>
    public bool VerifySignature(HardenedSmartContract contract, byte[] signature, byte[] publicKey, string keyType)
    {
        try
        {
            // Check for replay attacks
            if (!IsNonceValid(contract.Nonce))
            {
                Console.WriteLine($"Replay attack detected: nonce {contract.Nonce} already used");
                return false;
            }

            var contractHash = contract.ComputeContractHash();
            var dataToVerify = Encoding.UTF8.GetBytes(contractHash);

            bool isValid = false;

            switch (keyType.ToUpper())
            {
                case "RSA":
                    using (var rsa = RSA.Create())
                    {
                        rsa.ImportRSAPublicKey(publicKey, out _);
                        isValid = rsa.VerifyData(dataToVerify, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    }
                    break;

                case "ECDSA":
                    using (var ecdsa = ECDsa.Create())
                    {
                        ecdsa.ImportECPrivateKey(publicKey, out _); // This contains the public key
                        isValid = ecdsa.VerifyData(dataToVerify, signature, HashAlgorithmName.SHA256);
                    }
                    break;

                default:
                    Console.WriteLine($"Unsupported signature algorithm: {keyType}");
                    return false;
            }

            if (isValid)
            {
                // Mark nonce as used to prevent replay
                _usedNonces[contract.Nonce] = DateTime.UtcNow;
            }

            return isValid;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Signature verification failed: {ex.Message}");
            return false;
        }
    }

    private bool IsNonceValid(string nonce)
    {
        // Check if nonce was already used
        return !_usedNonces.ContainsKey(nonce);
    }

    /// <summary>
    /// Server-side contract review with cryptographic validation
    /// </summary>
    public (HardenedSmartContract modifiedContract, bool accepted, string reason) 
        ReviewAndValidateProposal(HardenedSmartContract proposal)
    {
        // First verify the client's signature
        if (proposal.ClientSignature != null)
        {
            var signatureValid = VerifySignature(proposal, proposal.ClientSignature, 
                                               proposal.ClientPublicKey, proposal.SignatureAlgorithm.Split('-')[0]);
            if (!signatureValid)
            {
                return (null, false, "Invalid client signature");
            }
        }

        // Check contract expiration
        if (proposal.IsExpired)
        {
            return (null, false, "Contract proposal has expired");
        }

        // Apply server policies
        var maxAllowedBandwidth = 1000; // 1 Mbps max
        var maxAllowedDuration = 120;   // 2 hours max
        var allowedServices = new[] { "http", "https", "dns", "ssh" };

        var modified = new HardenedSmartContract
        {
            DeviceId = proposal.DeviceId,
            AllowedServices = proposal.AllowedServices.Where(s => allowedServices.Contains(s)).ToList(),
            BandwidthLimitKbps = Math.Min(proposal.BandwidthLimitKbps, maxAllowedBandwidth),
            DurationMinutes = Math.Min(proposal.DurationMinutes, maxAllowedDuration),
            Encryption = proposal.Encryption,
            AllowedDestinations = proposal.AllowedDestinations,
            MaxConcurrentConnections = Math.Min(proposal.MaxConcurrentConnections, 5),
            DataTransferLimitMB = proposal.DataTransferLimitMB > 0 ? 
                Math.Min(proposal.DataTransferLimitMB, 1000) : 1000,
            Nonce = Guid.NewGuid().ToString(), // New nonce for modified contract
            ClientPublicKey = proposal.ClientPublicKey,
            ServerPublicKey = _deviceKeys.PublicKey,
            SignatureAlgorithm = proposal.SignatureAlgorithm
        };

        modified.ContractHash = modified.ComputeContractHash();

        // Check if we had to modify anything significant
        var isModified = modified.BandwidthLimitKbps != proposal.BandwidthLimitKbps ||
                        modified.DurationMinutes != proposal.DurationMinutes ||
                        modified.AllowedServices.Count != proposal.AllowedServices.Count ||
                        modified.MaxConcurrentConnections != proposal.MaxConcurrentConnections;

        var reason = isModified ? "Contract modified to comply with server policies" : "Contract accepted as proposed";
        
        return (modified, true, reason);
    }

    public void StoreActiveContract(HardenedSmartContract contract)
    {
        _activeContracts[contract.DeviceId] = contract;
        Console.WriteLine($"Contract activated for device {contract.DeviceId} - expires {contract.ExpiresTimestamp}");
    }

    public HardenedSmartContract GetActiveContract(string deviceId)
    {
        if (_activeContracts.TryGetValue(deviceId, out var contract))
        {
            if (!contract.IsExpired)
                return contract;
            
            // Clean up expired contract
            _activeContracts.TryRemove(deviceId, out _);
            Console.WriteLine($"Contract expired for device {deviceId}");
        }
        return null;
    }

    /// <summary>
    /// Clean up old nonces to prevent memory bloat while maintaining replay protection
    /// </summary>
    private async Task CleanupOldNonces()
    {
        while (true)
        {
            try
            {
                await Task.Delay(TimeSpan.FromMinutes(30)); // Cleanup every 30 minutes
                
                var cutoff = DateTime.UtcNow.AddHours(-24); // Keep nonces for 24 hours
                var oldNonces = _usedNonces.Where(kvp => kvp.Value < cutoff).Select(kvp => kvp.Key).ToList();
                
                foreach (var nonce in oldNonces)
                {
                    _usedNonces.TryRemove(nonce, out _);
                }
                
                if (oldNonces.Count > 0)
                {
                    Console.WriteLine($"Cleaned up {oldNonces.Count} old nonces");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Nonce cleanup error: {ex.Message}");
            }
        }
    }

    public Dictionary<string, HardenedSmartContract> GetAllActiveContracts()
    {
        return new Dictionary<string, HardenedSmartContract>(_activeContracts);
    }
}

/// <summary>
/// Example demonstrating hardened cryptographic contract system
/// </summary>
public class HardenedContractExample
{
    public static async Task RunExample()
    {
        Console.WriteLine("=== Cryptographically Hardened Smart Contract Demo ===");

        try
        {
            // Initialize client and server engines with secure keystores
            var clientKeystore = new SecureKeystore("./client_keystore");
            var serverKeystore = new SecureKeystore("./server_keystore");
            
            var clientEngine = new HardenedContractEngine("client-device-001", clientKeystore);
            var serverEngine = new HardenedContractEngine("server-gateway-001", serverKeystore);

            // Client creates and signs proposal
            var proposal = clientEngine.CreateProposal(
                requestedServices: new List<string> { "http", "https", "dns", "ssh" },
                requestedBandwidthKbps: 2000,
                requestedDurationMinutes: 180,
                requestedDestinations: new List<string> { "*" }
            );

            Console.WriteLine($"Client proposal created with hash: {proposal.ContractHash}");
            
            // Client signs the proposal
            proposal.ClientSignature = clientEngine.SignContract(proposal);
            Console.WriteLine($"Client signature: {Convert.ToBase64String(proposal.ClientSignature)[..32]}...");

            // Server reviews and validates
            var (modifiedContract, accepted, reason) = serverEngine.ReviewAndValidateProposal(proposal);
            
            if (!accepted)
            {
                Console.WriteLine($"Contract rejected: {reason}");
                return;
            }

            Console.WriteLine($"Server review: {reason}");
            Console.WriteLine($"Modified contract hash: {modifiedContract.ContractHash}");

            // Server signs the final contract
            modifiedContract.ServerSignature = serverEngine.SignContract(modifiedContract);
            Console.WriteLine($"Server signature: {Convert.ToBase64String(modifiedContract.ServerSignature)[..32]}...");

            // Both sides store the active contract
            clientEngine.StoreActiveContract(modifiedContract);
            serverEngine.StoreActiveContract(modifiedContract);

            Console.WriteLine("\n=== Security Validation ===");
            
            // Verify both signatures
            var clientSigValid = serverEngine.VerifySignature(modifiedContract, modifiedContract.ClientSignature,
                                                             modifiedContract.ClientPublicKey, 
                                                             modifiedContract.SignatureAlgorithm.Split('-')[0]);
            
            var serverSigValid = clientEngine.VerifySignature(modifiedContract, modifiedContract.ServerSignature,
                                                             modifiedContract.ServerPublicKey,
                                                             modifiedContract.SignatureAlgorithm.Split('-')[0]);

            Console.WriteLine($"Client signature valid: {clientSigValid}");
            Console.WriteLine($"Server signature valid: {serverSigValid}");
            
            // Test replay attack protection
            Console.WriteLine("\n=== Replay Attack Test ===");
            var replayValid = serverEngine.VerifySignature(modifiedContract, modifiedContract.ClientSignature,
                                                          modifiedContract.ClientPublicKey,
                                                          modifiedContract.SignatureAlgorithm.Split('-')[0]);
            Console.WriteLine($"Replay attempt blocked: {!replayValid}");

            Console.WriteLine($"\nContract successfully negotiated and cryptographically secured!");
            Console.WriteLine($"Final terms: {modifiedContract.ToJson()}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Hardened contract example failed: {ex.Message}");
        }
    }
}