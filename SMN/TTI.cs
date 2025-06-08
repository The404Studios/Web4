using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;
using System.Net;
using System.Net.NetworkInformation;

/// <summary>
/// Cross-platform TAP/TUN virtual network interface wrapper for C#
/// Enables full VPN capabilities for the mesh network
/// </summary>
public enum TunTapMode
{
    TUN,  // Layer 3 (IP packets)
    TAP   // Layer 2 (Ethernet frames)
}

public interface ITunTapInterface : IDisposable
{
    Task<byte[]> ReadPacketAsync(CancellationToken cancellationToken = default);
    Task WritePacketAsync(byte[] packet, CancellationToken cancellationToken = default);
    string InterfaceName { get; }
    bool IsConnected { get; }
    IPAddress LocalIP { get; set; }
    IPAddress RemoteIP { get; set; }
}

/// <summary>
/// Windows TAP interface implementation using OpenVPN TAP driver
/// </summary>
public class WindowsTapInterface : ITunTapInterface
{
    private const uint FILE_ATTRIBUTE_SYSTEM = 0x4;
    private const uint FILE_FLAG_OVERLAPPED = 0x40000000;
    private const uint GENERIC_READ = 0x80000000;
    private const uint GENERIC_WRITE = 0x40000000;
    private const uint OPEN_EXISTING = 3;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern SafeFileHandle CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(
        SafeFileHandle hDevice,
        uint dwIoControlCode,
        IntPtr lpInBuffer,
        uint nInBufferSize,
        IntPtr lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped);

    private SafeFileHandle _tapHandle;
    private FileStream _tapStream;
    private readonly string _devicePath;

    public string InterfaceName { get; private set; }
    public bool IsConnected => _tapHandle != null && !_tapHandle.IsInvalid;
    public IPAddress LocalIP { get; set; }
    public IPAddress RemoteIP { get; set; }

    public WindowsTapInterface(string tapDeviceGuid = null)
    {
        // Default to first available TAP device if none specified
        _devicePath = tapDeviceGuid != null 
            ? $"\\\\.\\Global\\{tapDeviceGuid}.tap"
            : FindTapDevice();
        
        InterfaceName = $"TAP-{tapDeviceGuid?[..8] ?? "Default"}";
    }

    private string FindTapDevice()
    {
        // Look for OpenVPN TAP devices in registry
        const string tapDriverKey = @"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}";
        
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(tapDriverKey);
            if (key != null)
            {
                foreach (var subKeyName in key.GetSubKeyNames())
                {
                    using var subKey = key.OpenSubKey(subKeyName);
                    var componentId = subKey?.GetValue("ComponentId") as string;
                    
                    if (componentId?.StartsWith("tap") == true)
                    {
                        var netCfgInstanceId = subKey.GetValue("NetCfgInstanceId") as string;
                        if (netCfgInstanceId != null)
                        {
                            return $"\\\\.\\Global\\{netCfgInstanceId}.tap";
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Failed to find TAP device: {ex.Message}");
        }

        throw new InvalidOperationException("No TAP devices found. Please install OpenVPN TAP driver.");
    }

    public async Task ConnectAsync()
    {
        if (IsConnected) return;

        _tapHandle = CreateFile(
            _devicePath,
            GENERIC_READ | GENERIC_WRITE,
            0, // No sharing
            IntPtr.Zero,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
            IntPtr.Zero);

        if (_tapHandle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            throw new InvalidOperationException($"Failed to open TAP device: {error}");
        }

        _tapStream = new FileStream(_tapHandle, FileAccess.ReadWrite, 1500, true);
        
        // Set TAP interface to connected state
        const uint TAP_IOCTL_SET_MEDIA_STATUS = 0x80044C30;
        var connected = BitConverter.GetBytes(1);
        
        var buffer = Marshal.AllocHGlobal(connected.Length);
        try
        {
            Marshal.Copy(connected, 0, buffer, connected.Length);
            DeviceIoControl(_tapHandle, TAP_IOCTL_SET_MEDIA_STATUS, buffer, 
                           (uint)connected.Length, IntPtr.Zero, 0, out _, IntPtr.Zero);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        Console.WriteLine($"TAP interface {InterfaceName} connected successfully");
    }

    public async Task<byte[]> ReadPacketAsync(CancellationToken cancellationToken = default)
    {
        if (!IsConnected)
            throw new InvalidOperationException("TAP interface not connected");

        var buffer = new byte[1500]; // MTU size
        var bytesRead = await _tapStream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);
        
        if (bytesRead > 0)
        {
            var packet = new byte[bytesRead];
            Array.Copy(buffer, packet, bytesRead);
            return packet;
        }

        return null;
    }

    public async Task WritePacketAsync(byte[] packet, CancellationToken cancellationToken = default)
    {
        if (!IsConnected)
            throw new InvalidOperationException("TAP interface not connected");

        await _tapStream.WriteAsync(packet, 0, packet.Length, cancellationToken);
    }

    public void Dispose()
    {
        _tapStream?.Dispose();
        _tapHandle?.Dispose();
        Console.WriteLine($"TAP interface {InterfaceName} disconnected");
    }
}

/// <summary>
/// Linux TUN interface implementation
/// </summary>
public class LinuxTunInterface : ITunTapInterface
{
    [DllImport("libc", SetLastError = true)]
    private static extern int open(string pathname, int flags);

    [DllImport("libc", SetLastError = true)]
    private static extern int close(int fd);

    [DllImport("libc", SetLastError = true)]
    private static extern int ioctl(int fd, uint request, IntPtr argp);

    [DllImport("libc", SetLastError = true)]
    private static extern IntPtr read(int fd, IntPtr buf, int count);

    [DllImport("libc", SetLastError = true)]
    private static extern IntPtr write(int fd, IntPtr buf, int count);

    private const int O_RDWR = 2;
    private const uint TUNSETIFF = 0x400454ca;
    private const ushort IFF_TUN = 0x0001;
    private const ushort IFF_NO_PI = 0x1000;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    private struct ifreq
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 16)]
        public string ifr_name;
        public ushort ifr_flags;
    }

    private int _tunFd = -1;
    private FileStream _tunStream;

    public string InterfaceName { get; private set; }
    public bool IsConnected => _tunFd >= 0;
    public IPAddress LocalIP { get; set; }
    public IPAddress RemoteIP { get; set; }

    public LinuxTunInterface(string interfaceName = "tun0")
    {
        InterfaceName = interfaceName;
    }

    public async Task ConnectAsync()
    {
        if (IsConnected) return;

        _tunFd = open("/dev/net/tun", O_RDWR);
        if (_tunFd < 0)
        {
            throw new InvalidOperationException("Failed to open /dev/net/tun. Make sure you have root privileges.");
        }

        var ifr = new ifreq
        {
            ifr_name = InterfaceName,
            ifr_flags = IFF_TUN | IFF_NO_PI
        };

        var ifrPtr = Marshal.AllocHGlobal(Marshal.SizeOf(ifr));
        try
        {
            Marshal.StructureToPtr(ifr, ifrPtr, false);
            
            if (ioctl(_tunFd, TUNSETIFF, ifrPtr) < 0)
            {
                close(_tunFd);
                _tunFd = -1;
                throw new InvalidOperationException($"Failed to configure TUN interface {InterfaceName}");
            }
        }
        finally
        {
            Marshal.FreeHGlobal(ifrPtr);
        }

        _tunStream = new FileStream(new SafeFileHandle((IntPtr)_tunFd, true), FileAccess.ReadWrite);
        
        Console.WriteLine($"TUN interface {InterfaceName} connected successfully");
    }

    public async Task<byte[]> ReadPacketAsync(CancellationToken cancellationToken = default)
    {
        if (!IsConnected)
            throw new InvalidOperationException("TUN interface not connected");

        var buffer = new byte[1500];
        var bytesRead = await _tunStream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);
        
        if (bytesRead > 0)
        {
            var packet = new byte[bytesRead];
            Array.Copy(buffer, packet, bytesRead);
            return packet;
        }

        return null;
    }

    public async Task WritePacketAsync(byte[] packet, CancellationToken cancellationToken = default)
    {
        if (!IsConnected)
            throw new InvalidOperationException("TUN interface not connected");

        await _tunStream.WriteAsync(packet, 0, packet.Length, cancellationToken);
    }

    public void Dispose()
    {
        _tunStream?.Dispose();
        if (_tunFd >= 0)
        {
            close(_tunFd);
            _tunFd = -1;
        }
        Console.WriteLine($"TUN interface {InterfaceName} disconnected");
    }
}

/// <summary>
/// Factory for creating platform-appropriate TUN/TAP interfaces
/// </summary>
public static class TunTapFactory
{
    public static ITunTapInterface CreateInterface(TunTapMode mode, string name = null)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            if (mode == TunTapMode.TAP)
                return new WindowsTapInterface(name);
            else
                throw new NotSupportedException("TUN mode not directly supported on Windows. Use TAP mode.");
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            return new LinuxTunInterface(name ?? "meshnet0");
        }
        else
        {
            throw new PlatformNotSupportedException($"TUN/TAP not supported on {RuntimeInformation.OSDescription}");
        }
    }
}

/// <summary>
/// Network packet parser for handling different protocol types
/// </summary>
public static class PacketParser
{
    public enum EtherType : ushort
    {
        IPv4 = 0x0800,
        IPv6 = 0x86DD,
        ARP = 0x0806
    }

    public enum IPProtocol : byte
    {
        TCP = 6,
        UDP = 17,
        ICMP = 1
    }

    public class ParsedPacket
    {
        public EtherType EtherType { get; set; }
        public IPProtocol? Protocol { get; set; }
        public IPAddress SourceIP { get; set; }
        public IPAddress DestinationIP { get; set; }
        public ushort? SourcePort { get; set; }
        public ushort? DestinationPort { get; set; }
        public byte[] RawData { get; set; }
        public bool IsValid { get; set; }
    }

    public static ParsedPacket ParseEthernetFrame(byte[] frame)
    {
        var packet = new ParsedPacket { RawData = frame };

        try
        {
            if (frame.Length < 14) // Minimum Ethernet header
            {
                packet.IsValid = false;
                return packet;
            }

            // Extract EtherType (bytes 12-13)
            var etherType = (EtherType)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(frame, 12));
            packet.EtherType = etherType;

            if (etherType == EtherType.IPv4)
            {
                ParseIPv4Packet(frame, 14, packet);
            }
            else if (etherType == EtherType.IPv6)
            {
                ParseIPv6Packet(frame, 14, packet);
            }

            packet.IsValid = true;
        }
        catch
        {
            packet.IsValid = false;
        }

        return packet;
    }

    public static ParsedPacket ParseIPPacket(byte[] ipPacket)
    {
        var packet = new ParsedPacket { RawData = ipPacket };

        try
        {
            if (ipPacket.Length < 20) // Minimum IP header
            {
                packet.IsValid = false;
                return packet;
            }

            var version = (ipPacket[0] >> 4) & 0xF;
            
            if (version == 4)
            {
                packet.EtherType = EtherType.IPv4;
                ParseIPv4Packet(ipPacket, 0, packet);
            }
            else if (version == 6)
            {
                packet.EtherType = EtherType.IPv6;
                ParseIPv6Packet(ipPacket, 0, packet);
            }

            packet.IsValid = true;
        }
        catch
        {
            packet.IsValid = false;
        }

        return packet;
    }

    private static void ParseIPv4Packet(byte[] data, int offset, ParsedPacket packet)
    {
        if (data.Length < offset + 20) return;

        // Protocol (byte 9 from IP header start)
        packet.Protocol = (IPProtocol)data[offset + 9];

        // Source IP (bytes 12-15)
        var srcBytes = new byte[4];
        Array.Copy(data, offset + 12, srcBytes, 0, 4);
        packet.SourceIP = new IPAddress(srcBytes);

        // Destination IP (bytes 16-19)
        var dstBytes = new byte[4];
        Array.Copy(data, offset + 16, dstBytes, 0, 4);
        packet.DestinationIP = new IPAddress(dstBytes);

        // Extract ports for TCP/UDP
        var headerLength = (data[offset] & 0xF) * 4;
        if (packet.Protocol == IPProtocol.TCP || packet.Protocol == IPProtocol.UDP)
        {
            if (data.Length >= offset + headerLength + 4)
            {
                packet.SourcePort = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(data, offset + headerLength));
                packet.DestinationPort = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(data, offset + headerLength + 2));
            }
        }
    }

    private static void ParseIPv6Packet(byte[] data, int offset, ParsedPacket packet)
    {
        if (data.Length < offset + 40) return; // IPv6 header is 40 bytes

        // Next Header (protocol)
        packet.Protocol = (IPProtocol)data[offset + 6];

        // Source IP (bytes 8-23)
        var srcBytes = new byte[16];
        Array.Copy(data, offset + 8, srcBytes, 0, 16);
        packet.SourceIP = new IPAddress(srcBytes);

        // Destination IP (bytes 24-39)
        var dstBytes = new byte[16];
        Array.Copy(data, offset + 24, dstBytes, 0, 16);
        packet.DestinationIP = new IPAddress(dstBytes);

        // Extract ports for TCP/UDP
        if (packet.Protocol == IPProtocol.TCP || packet.Protocol == IPProtocol.UDP)
        {
            if (data.Length >= offset + 40 + 4)
            {
                packet.SourcePort = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(data, offset + 40));
                packet.DestinationPort = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(data, offset + 40 + 2));
            }
        }
    }
}

/// <summary>
/// Example usage of TUN/TAP interface with packet inspection
/// </summary>
public class TunTapExample
{
    public static async Task RunExample()
    {
        Console.WriteLine("=== TUN/TAP Virtual Network Interface Demo ===");

        try
        {
            // Create appropriate interface for platform
            var mode = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? TunTapMode.TAP : TunTapMode.TUN;
            using var tunTap = TunTapFactory.CreateInterface(mode, "meshnet0");

            if (tunTap is WindowsTapInterface tapInterface)
            {
                await tapInterface.ConnectAsync();
            }
            else if (tunTap is LinuxTunInterface tunInterface)
            {
                await tunInterface.ConnectAsync();
            }

            Console.WriteLine($"Virtual interface {tunTap.InterfaceName} created and connected");
            Console.WriteLine("Monitoring packets for 30 seconds...");

            var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var packetCount = 0;

            while (!cts.Token.IsCancellationRequested)
            {
                try
                {
                    var packet = await tunTap.ReadPacketAsync(cts.Token);
                    if (packet != null)
                    {
                        packetCount++;
                        
                        var parsed = mode == TunTapMode.TAP 
                            ? PacketParser.ParseEthernetFrame(packet)
                            : PacketParser.ParseIPPacket(packet);

                        if (parsed.IsValid)
                        {
                            Console.WriteLine($"Packet #{packetCount}: {parsed.EtherType} " +
                                            $"{parsed.SourceIP} → {parsed.DestinationIP} " +
                                            $"({parsed.Protocol}) " +
                                            $"{parsed.SourcePort}→{parsed.DestinationPort}");
                        }

                        // Echo packet back (for testing)
                        // await tunTap.WritePacketAsync(packet, cts.Token);
                    }
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error reading packet: {ex.Message}");
                    await Task.Delay(100, cts.Token);
                }
            }

            Console.WriteLine($"Captured {packetCount} packets");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"TUN/TAP example failed: {ex.Message}");
            Console.WriteLine("Note: This requires admin privileges and appropriate drivers installed");
        }
    }
}