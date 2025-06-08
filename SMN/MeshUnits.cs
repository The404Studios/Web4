using System;
using System.Collections.Generic;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Moq;
using System.Net.Sockets;
using System.IO;

namespace SmartMeshNetwork.Tests
{
    /// <summary>
    /// Unit tests for Smart Network Contract system
    /// Addresses fuzz testing and cryptographic validation
    /// </summary>
    public class SmartContractTests
    {
        [Fact]
        public void SmartContract_ComputeContractHash_IsConsistent()
        {
            // Arrange
            var contract = CreateSampleContract();

            // Act
            var hash1 = contract.ComputeContractHash();
            var hash2 = contract.ComputeContractHash();

            // Assert
            Assert.Equal(hash1, hash2);
            Assert.NotEmpty(hash1);
        }

        [Fact]
        public void SmartContract_ComputeContractHash_ChangesWithModification()
        {
            // Arrange
            var contract1 = CreateSampleContract();
            var contract2 = CreateSampleContract();
            contract2.BandwidthLimitKbps = 1000; // Different value

            // Act
            var hash1 = contract1.ComputeContractHash();
            var hash2 = contract2.ComputeContractHash();

            // Assert
            Assert.NotEqual(hash1, hash2);
        }

        [Fact]
        public async Task ContractNegotiationEngine_CreateProposal_GeneratesValidContract()
        {
            // Arrange
            var keystore = new SecureKeystore("./test_keystore");
            var engine = new ContractNegotiationEngine("test-device", keystore);

            // Act
            var proposal = engine.CreateProposal(
                new List<string> { "http", "https" },
                500,
                60,
                new List<string> { "*" }
            );

            // Assert
            Assert.Equal("test-device", proposal.DeviceId);
            Assert.Equal(500, proposal.BandwidthLimitKbps);
            Assert.Equal(60, proposal.DurationMinutes);
            Assert.NotEmpty(proposal.Nonce);
            Assert.NotNull(proposal.ClientPublicKey);
            Assert.NotEmpty(proposal.ContractHash);
        }

        [Fact]
        public void ContractNegotiationEngine_SignAndVerify_WorksCorrectly()
        {
            // Arrange
            var keystore = new SecureKeystore("./test_keystore");
            var engine = new ContractNegotiationEngine("test-device", keystore);
            var contract = CreateSampleContract();
            contract.ClientPublicKey = engine._deviceKeys.PublicKey;

            // Act
            var signature = engine.SignContract(contract);
            var isValid = engine.VerifySignature(contract, signature, 
                                               contract.ClientPublicKey, 
                                               engine._deviceKeys.KeyType);

            // Assert
            Assert.NotNull(signature);
            Assert.True(signature.Length > 0);
            Assert.True(isValid);
        }

        [Fact]
        public void ContractNegotiationEngine_ReplayProtection_BlocksReusedNonce()
        {
            // Arrange
            var keystore = new SecureKeystore("./test_keystore");
            var engine = new ContractNegotiationEngine("test-device", keystore);
            var contract = CreateSampleContract();
            contract.ClientPublicKey = engine._deviceKeys.PublicKey;
            contract.Nonce = "test-nonce-123";

            var signature = engine.SignContract(contract);

            // Act - First verification should succeed
            var firstVerification = engine.VerifySignature(contract, signature, 
                                                          contract.ClientPublicKey, 
                                                          engine._deviceKeys.KeyType);

            // Act - Second verification with same nonce should fail (replay attack)
            var replayAttempt = engine.VerifySignature(contract, signature, 
                                                      contract.ClientPublicKey, 
                                                      engine._deviceKeys.KeyType);

            // Assert
            Assert.True(firstVerification);
            Assert.False(replayAttempt); // Should be blocked
        }

        [Theory]
        [InlineData("")]
        [InlineData(null)]
        [InlineData("invalid-service")]
        public void SmartContract_IsServiceAllowed_HandlesEdgeCases(string service)
        {
            // Arrange
            var contract = CreateSampleContract();
            contract.AllowedServices = new List<string> { "http", "https" };

            // Act & Assert
            if (string.IsNullOrEmpty(service))
            {
                Assert.False(contract.IsServiceAllowed(service ?? ""));
            }
            else
            {
                Assert.False(contract.IsServiceAllowed(service));
            }
        }

        private SmartNetworkContract CreateSampleContract()
        {
            return new SmartNetworkContract
            {
                DeviceId = "test-device",
                AllowedServices = new List<string> { "http", "https", "dns" },
                BandwidthLimitKbps = 500,
                DurationMinutes = 60,
                AllowedDestinations = new List<string> { "*" },
                Nonce = Guid.NewGuid().ToString()
            };
        }
    }

    /// <summary>
    /// Unit tests for Token Bucket bandwidth limiter
    /// </summary>
    public class TokenBucketTests
    {
        [Fact]
        public void TokenBucket_TryConsume_AllowsWithinLimits()
        {
            // Arrange
            var limiter = new TokenBucketBandwidthLimiter(1000); // 1 Mbps

            // Act
            var canSend = limiter.TryConsume(1000); // 1KB packet

            // Assert
            Assert.True(canSend);
        }

        [Fact]
        public void TokenBucket_TryConsume_BlocksOverLimit()
        {
            // Arrange
            var limiter = new TokenBucketBandwidthLimiter(1); // 1 Kbps (very low)

            // Act
            var firstPacket = limiter.TryConsume(1024); // 1KB packet
            var secondPacket = limiter.TryConsume(1024); // Should be blocked

            // Assert
            Assert.True(firstPacket);
            Assert.False(secondPacket);
        }

        [Fact]
        public void TokenBucket_GetDelayForPacket_CalculatesCorrectDelay()
        {
            // Arrange
            var limiter = new TokenBucketBandwidthLimiter(1000); // 1 Mbps
            limiter.TryConsume(128000); // Consume all tokens

            // Act
            var delay = limiter.GetDelayForPacket(1000);

            // Assert
            Assert.True(delay > TimeSpan.Zero);
            Assert.True(delay < TimeSpan.FromSeconds(2)); // Should be reasonable
        }

        [Fact]
        public void QoSPacketScheduler_PrioritizesCorrectly()
        {
            // Arrange
            var scheduler = new QoSPacketScheduler(1000);
            
            var bulkPacket = new QoSPacket
            {
                Data = new byte[100],
                Priority = PacketPriority.Bulk,
                DestinationEndpoint = "bulk.example.com"
            };

            var controlPacket = new QoSPacket
            {
                Data = new byte[50],
                Priority = PacketPriority.Control,
                DestinationEndpoint = "control.example.com"
            };

            // Act
            scheduler.EnqueuePacket(bulkPacket);
            scheduler.EnqueuePacket(controlPacket);

            // Assert - Control packet should have higher priority queue
            Assert.Equal(1, scheduler.GetQueueLength(PacketPriority.Control));
            Assert.Equal(1, scheduler.GetQueueLength(PacketPriority.Bulk));
        }
    }

    /// <summary>
    /// Fuzz tests for packet parser
    /// Addresses security concern about crashes from malformed packets
    /// </summary>
    public class PacketParserFuzzTests
    {
        [Fact]
        public void PacketParser_ParseEthernetFrame_HandlesRandomData()
        {
            // Arrange
            var random = new Random(42); // Fixed seed for reproducible tests
            var testCases = 1000;

            // Act & Assert
            for (int i = 0; i < testCases; i++)
            {
                var randomData = new byte[random.Next(0, 2000)];
                random.NextBytes(randomData);

                // Should not throw exception
                var result = PacketParser.ParseEthernetFrame(randomData);
                
                // Should handle gracefully
                Assert.NotNull(result);
                // Invalid packets should be marked as such
                if (randomData.Length < 14)
                {
                    Assert.False(result.IsValid);
                }
            }
        }

        [Fact]
        public void PacketParser_ParseIPPacket_HandlesRandomData()
        {
            // Arrange
            var random = new Random(42);
            var testCases = 1000;

            // Act & Assert
            for (int i = 0; i < testCases; i++)
            {
                var randomData = new byte[random.Next(0, 1500)];
                random.NextBytes(randomData);

                // Should not throw exception
                var result = PacketParser.ParseIPPacket(randomData);
                
                Assert.NotNull(result);
                if (randomData.Length < 20)
                {
                    Assert.False(result.IsValid);
                }
            }
        }

        [Theory]
        [InlineData(new byte[0])]
        [InlineData(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF })]
        [InlineData(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 })]
        public void PacketParser_ParseEthernetFrame_HandlesEdgeCases(byte[] data)
        {
            // Act
            var result = PacketParser.ParseEthernetFrame(data);

            // Assert
            Assert.NotNull(result);
            Assert.False(result.IsValid); // Should be invalid for edge cases
        }

        [Fact]
        public void PacketParser_ParseValidIPv4Packet_ParsesCorrectly()
        {
            // Arrange - Valid IPv4 packet header
            var ipv4Packet = new byte[]
            {
                0x45, 0x00, 0x00, 0x3C, // Version, IHL, TOS, Total Length
                0x1C, 0x46, 0x40, 0x00, // ID, Flags, Fragment Offset
                0x40, 0x06, 0x00, 0x00, // TTL, Protocol (TCP), Checksum
                0xC0, 0xA8, 0x01, 0x64, // Source IP (192.168.1.100)
                0xC0, 0xA8, 0x01, 0x01, // Dest IP (192.168.1.1)
                0x1F, 0x90, 0x00, 0x50  // TCP ports (8080 -> 80)
            };

            // Act
            var result = PacketParser.ParseIPPacket(ipv4Packet);

            // Assert
            Assert.True(result.IsValid);
            Assert.Equal(PacketParser.EtherType.IPv4, result.EtherType);
            Assert.Equal(PacketParser.IPProtocol.TCP, result.Protocol);
            Assert.Equal(IPAddress.Parse("192.168.1.100"), result.SourceIP);
            Assert.Equal(IPAddress.Parse("192.168.1.1"), result.DestinationIP);
            Assert.Equal((ushort)8080, result.SourcePort);
            Assert.Equal((ushort)80, result.DestinationPort);
        }
    }

    /// <summary>
    /// Mock-based tests for P2P NAT traversal
    /// </summary>
    public class NATTraversalTests
    {
        [Fact]
        public async Task STUNClient_DiscoverPublicEndPoint_HandlesFailure()
        {
            // Arrange
            var stunClient = new ComprehensiveSTUNClient();

            // Act
            var result = await stunClient.PerformComprehensiveNATDiscoveryAsync(12345);

            // Assert - Should handle gracefully even if STUN servers are unreachable
            Assert.NotNull(result);
            // In test environment, STUN might fail, but should not crash
        }

        [Fact]
        public void RateLimiter_TryAcquire_EnforcesLimits()
        {
            // Arrange
            var limiter = new RateLimiter(2, TimeSpan.FromSeconds(1));

            // Act
            var first = limiter.TryAcquire();
            var second = limiter.TryAcquire();
            var third = limiter.TryAcquire(); // Should be blocked

            // Assert
            Assert.True(first);
            Assert.True(second);
            Assert.False(third);
        }

        [Fact]
        public async Task RateLimiter_TryAcquire_ResetsAfterWindow()
        {
            // Arrange
            var limiter = new RateLimiter(1, TimeSpan.FromMilliseconds(100));

            // Act
            var first = limiter.TryAcquire();
            await Task.Delay(150); // Wait for window to reset
            var second = limiter.TryAcquire();

            // Assert
            Assert.True(first);
            Assert.True(second);
        }
    }

    /// <summary>
    /// Integration tests for mesh node lifecycle
    /// </summary>
    public class MeshNodeIntegrationTests
    {
        [Fact]
        public async Task MeshNode_StartStop_CompletesGracefully()
        {
            // Arrange
            var config = new MeshNodeConfiguration
            {
                EnableVPN = false, // Disable VPN for test environment
                P2PPort = 0 // Random port
            };

            using var meshNode = new MeshNode("test-node", config);

            // Act
            var started = await meshNode.StartAsync();
            Assert.True(started);

            await meshNode.StopAsync();

            // Assert - Should complete without exception
        }

        [Fact]
        public async Task MeshNode_AcceptPeerContract_ValidatesCorrectly()
        {
            // Arrange
            var config = new MeshNodeConfiguration { EnableVPN = false };
            using var meshNode = new MeshNode("test-server", config);
            await meshNode.StartAsync();

            var clientKeystore = new SecureKeystore("./test_client_keystore");
            var clientEngine = new ContractNegotiationEngine("test-client", clientKeystore);
            
            var proposal = clientEngine.CreateProposal(
                new List<string> { "http", "https" },
                500,
                60
            );
            
            proposal.ClientSignature = clientEngine.SignContract(proposal);

            // Act
            var accepted = await meshNode.AcceptPeerContractAsync(proposal);

            // Assert
            Assert.True(accepted);

            await meshNode.StopAsync();
        }
    }

    /// <summary>
    /// Performance and stress tests
    /// </summary>
    public class PerformanceTests
    {
        [Fact]
        public void TokenBucket_HighThroughput_PerformsWell()
        {
            // Arrange
            var limiter = new TokenBucketBandwidthLimiter(10000); // 10 Mbps
            var packetSize = 1000;
            var iterations = 10000;

            // Act
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            
            for (int i = 0; i < iterations; i++)
            {
                limiter.TryConsume(packetSize);
            }
            
            stopwatch.Stop();

            // Assert - Should complete quickly
            Assert.True(stopwatch.ElapsedMilliseconds < 1000); // Less than 1 second
        }

        [Fact]
        public void PacketParser_ParseManyPackets_PerformsWell()
        {
            // Arrange
            var validPacket = new byte[]
            {
                0x45, 0x00, 0x00, 0x3C, 0x1C, 0x46, 0x40, 0x00,
                0x40, 0x06, 0x00, 0x00, 0xC0, 0xA8, 0x01, 0x64,
                0xC0, 0xA8, 0x01, 0x01, 0x1F, 0x90, 0x00, 0x50
            };
            
            var iterations = 10000;

            // Act
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            
            for (int i = 0; i < iterations; i++)
            {
                PacketParser.ParseIPPacket(validPacket);
            }
            
            stopwatch.Stop();

            // Assert
            Assert.True(stopwatch.ElapsedMilliseconds < 1000);
        }

        [Fact]
        public async Task ContractNegotiation_ManySignatures_PerformsWell()
        {
            // Arrange
            var keystore = new SecureKeystore("./test_perf_keystore");
            var engine = new ContractNegotiationEngine("perf-test", keystore);
            var contract = new SmartNetworkContract
            {
                DeviceId = "test",
                BandwidthLimitKbps = 500,
                DurationMinutes = 60,
                ClientPublicKey = engine._deviceKeys.PublicKey
            };

            var iterations = 100; // Crypto operations are slower

            // Act
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            
            for (int i = 0; i < iterations; i++)
            {
                contract.Nonce = Guid.NewGuid().ToString(); // Unique nonce each time
                var signature = engine.SignContract(contract);
                engine.VerifySignature(contract, signature, contract.ClientPublicKey, engine._deviceKeys.KeyType);
            }
            
            stopwatch.Stop();

            // Assert - Crypto operations are inherently slower
            Assert.True(stopwatch.ElapsedMilliseconds < 5000); // Less than 5 seconds for 100 operations
        }
    }

    /// <summary>
    /// Error handling and edge case tests
    /// </summary>
    public class ErrorHandlingTests
    {
        [Fact]
        public async Task ErrorHandler_ExecuteWithRetry_RetriesOnFailure()
        {
            // Arrange
            var attempts = 0;
            async Task<bool> FailingOperation()
            {
                attempts++;
                if (attempts < 3)
                    throw new InvalidOperationException("Temporary failure");
                return true;
            }

            // Act
            var result = await ErrorHandler.ExecuteWithRetry(FailingOperation, 3, TimeSpan.FromMilliseconds(10));

            // Assert
            Assert.True(result);
            Assert.Equal(3, attempts);
        }

        [Fact]
        public async Task ErrorHandler_ExecuteWithRetry_FailsAfterMaxRetries()
        {
            // Arrange
            async Task<bool> AlwaysFailingOperation()
            {
                throw new InvalidOperationException("Always fails");
            }

            // Act & Assert
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                ErrorHandler.ExecuteWithRetry(AlwaysFailingOperation, 2, TimeSpan.FromMilliseconds(10)));
        }

        [Fact]
        public void ConfigurationValidator_ValidateConfiguration_DetectsInvalidValues()
        {
            // Arrange
            var invalidConfig = new Dictionary<string, string>
            {
                ["P2PPort"] = "99999", // Invalid port
                ["VPNMode"] = "INVALID", // Invalid mode
                ["MaxBandwidthKbps"] = "-1", // Invalid bandwidth
                ["MaxDurationMinutes"] = "0" // Invalid duration
            };

            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(invalidConfig)
                .Build();

            // Act
            var errors = ConfigurationValidator.ValidateConfiguration(configuration);

            // Assert
            Assert.NotEmpty(errors);
            Assert.Contains(errors, e => e.Contains("P2PPort"));
            Assert.Contains(errors, e => e.Contains("VPNMode"));
            Assert.Contains(errors, e => e.Contains("MaxBandwidthKbps"));
            Assert.Contains(errors, e => e.Contains("MaxDurationMinutes"));
        }
    }

    /// <summary>
    /// Test utilities and helpers
    /// </summary>
    public static class TestHelpers
    {
        public static byte[] CreateRandomPacket(int size, Random random = null)
        {
            random ??= new Random();
            var packet = new byte[size];
            random.NextBytes(packet);
            return packet;
        }

        public static SmartNetworkContract CreateValidContract(string deviceId = "test-device")
        {
            return new SmartNetworkContract
            {
                DeviceId = deviceId,
                AllowedServices = new List<string> { "http", "https", "dns" },
                BandwidthLimitKbps = 500,
                DurationMinutes = 60,
                AllowedDestinations = new List<string> { "*" },
                Nonce = Guid.NewGuid().ToString()
            };
        }

        public static async Task<bool> WaitForCondition(Func<bool> condition, TimeSpan timeout)
        {
            var startTime = DateTime.UtcNow;
            while (DateTime.UtcNow - startTime < timeout)
            {
                if (condition())
                    return true;
                
                await Task.Delay(10);
            }
            return false;
        }
    }
}

/// <summary>
/// Test configuration for xUnit
/// </summary>
public class TestConfiguration
{
    public TestConfiguration()
    {
        // Ensure test directories exist
        Directory.CreateDirectory("./test_keystore");
        Directory.CreateDirectory("./test_client_keystore");
        Directory.CreateDirectory("./test_perf_keystore");
        Directory.CreateDirectory("./test_state");
    }
}