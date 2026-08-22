// Interop check: does Technitium's PROXY protocol parser accept the datagrams
// sni-router puts on the wire for `proto: udp` + `proxy_protocol: v1|v2`?
//
// Technitium's DNS-over-UDP-PROXY listener does exactly this per datagram
// (DnsServerCore/Dns/DnsServer.cs, ReadUdpRequestAsync):
//
//     recvBufferStream.Position = 0;
//     recvBufferStream.SetLength(result.ReceivedBytes);
//     ProxyProtocolStream proxy = await ProxyProtocolStream.CreateAsServerAsync(recvBufferStream);
//     if (!proxy.IsLocal) remoteEP = new IPEndPoint(proxy.SourceAddress, proxy.SourcePort);
//     recvBufferStream.Position = proxy.DataOffset;
//     DnsDatagram request = DnsDatagram.ReadFrom(recvBufferStream);
//
// so this harness replays that sequence against their parser compiled straight
// from their source tree (see the .csproj — it is a <Compile Include>, not a
// copy). The header bytes below are pinned to the same literal as the Rust test
// `proxy_protocol::tests::v2_udp_wire_bytes_are_pinned`; if the two ever drift
// apart, one of these two tests goes red.
//
//   dotnet run --project tests/technitium-interop
//
// Exit code 0 = every case behaved as expected.

using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.ProxyProtocol;

internal static class Program
{
    // A minimal DNS query for example.com A, as a resolver would send it.
    static readonly byte[] DnsQuery =
    {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07, (byte)'e', (byte)'x', (byte)'a', (byte)'m', (byte)'p', (byte)'l', (byte)'e',
        0x03, (byte)'c', (byte)'o', (byte)'m', 0x00, 0x00, 0x01, 0x00, 0x01,
    };

    // Exactly what sni-router emits for src 203.0.113.7:51234 -> dst
    // 198.51.100.1:53 with proxy_protocol: v2 on a udp listener.
    const string V2Udp = "0d0a0d0a000d0a515549540a2112000ccb007107c6336401c8220035";

    static int _failures;

    static async Task<int> Main()
    {
        // The fix: every datagram carries its own header, so every datagram
        // parses and the client IP survives.
        await Case("v2 per-datagram header (the DNS-over-UDP-PROXY case)",
            Hex(V2Udp).Concat(DnsQuery).ToArray(),
            expectSource: "203.0.113.7", expectPort: 51234, expectDataOffset: 28);

        // Same flow, second and third datagram — identical framing, no state
        // carried over from the first. This is what a stream-style "header once"
        // implementation gets wrong.
        await Case("v2 per-datagram header, repeated datagram",
            Hex(V2Udp).Concat(DnsQuery).ToArray(),
            expectSource: "203.0.113.7", expectPort: 51234, expectDataOffset: 28);

        await Case("v2 IPv6 client",
            V2(IPAddress.Parse("2001:db8::1"), 51234, IPAddress.Parse("2001:db8::53"), 53)
                .Concat(DnsQuery).ToArray(),
            expectSource: "2001:db8::1", expectPort: 51234, expectDataOffset: 52);

        await Case("v1 per-datagram header",
            Ascii("PROXY TCP4 203.0.113.7 198.51.100.1 51234 53\r\n").Concat(DnsQuery).ToArray(),
            expectSource: "203.0.113.7", expectPort: 51234, expectDataOffset: 46);

        // The two shapes of the old behaviour, kept as regression proof.
        await Rejects("bare query, no header (every datagram after the first, pre-1.8.0)",
            DnsQuery);

        await HeaderOnly("header alone in its own datagram (the first one, pre-1.8.0)",
            Hex(V2Udp));

        Console.WriteLine(_failures == 0
            ? "\nAll cases behaved as expected."
            : $"\n{_failures} case(s) FAILED.");
        return _failures == 0 ? 0 : 1;
    }

    // ---- cases -------------------------------------------------------------

    static async Task Case(string name, byte[] datagram, string expectSource, int expectPort, int expectDataOffset)
    {
        int before = _failures;
        try
        {
            using MemoryStream s = Received(datagram);
            ProxyProtocolStream p = await ProxyProtocolStream.CreateAsServerAsync(s);
            s.Position = p.DataOffset;

            byte[] payload = new byte[s.Length - s.Position];
            s.ReadExactly(payload);

            Check(name, "source address", p.SourceAddress?.ToString(), expectSource);
            Check(name, "source port", p.SourcePort.ToString(), expectPort.ToString());
            Check(name, "data offset", p.DataOffset.ToString(), expectDataOffset.ToString());
            Check(name, "payload", Convert.ToHexString(payload), Convert.ToHexString(DnsQuery));
            if (_failures == before)
                Pass(name);
        }
        catch (Exception ex)
        {
            Fail(name, $"threw {ex.GetType().Name}: {ex.Message}");
        }
    }

    static async Task Rejects(string name, byte[] datagram)
    {
        try
        {
            using MemoryStream s = Received(datagram);
            await ProxyProtocolStream.CreateAsServerAsync(s);
            Fail(name, "parsed, but Technitium must reject a datagram with no header");
        }
        catch (InvalidDataException)
        {
            Pass(name + " -> rejected, as expected");
        }
        catch (EndOfStreamException)
        {
            Pass(name + " -> rejected, as expected");
        }
        catch (Exception ex)
        {
            Fail(name, $"threw {ex.GetType().Name} instead of a parse rejection: {ex.Message}");
        }
    }

    static async Task HeaderOnly(string name, byte[] datagram)
    {
        try
        {
            using MemoryStream s = Received(datagram);
            ProxyProtocolStream p = await ProxyProtocolStream.CreateAsServerAsync(s);
            s.Position = p.DataOffset;
            long left = s.Length - s.Position;
            if (left == 0)
                Pass(name + " -> header parses but carries no query (0 payload bytes)");
            else
                Fail(name, $"expected an empty payload, got {left} bytes");
        }
        catch (Exception ex)
        {
            Pass(name + $" -> not usable either ({ex.GetType().Name})");
        }
    }

    // ---- helpers -----------------------------------------------------------

    /// A received datagram, framed the way Technitium frames one: a fixed
    /// receive buffer whose length is set to the bytes that arrived.
    static MemoryStream Received(byte[] datagram)
    {
        byte[] recvBuffer = new byte[4096 + 256];
        datagram.CopyTo(recvBuffer, 0);
        MemoryStream s = new MemoryStream(recvBuffer);
        s.Position = 0;
        s.SetLength(datagram.Length);
        return s;
    }

    static byte[] V2(IPAddress src, ushort srcPort, IPAddress dst, ushort dstPort)
    {
        byte[] sig = Hex("0d0a0d0a000d0a515549540a");
        bool v6 = src.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
        int addrLen = v6 ? 36 : 12;
        byte[] o = new byte[16 + addrLen];
        sig.CopyTo(o, 0);
        o[12] = 0x21;                          // version 2, PROXY command
        o[13] = (byte)((v6 ? 0x20 : 0x10) | 2); // AF_INET(6) + DGRAM
        o[14] = (byte)(addrLen >> 8);
        o[15] = (byte)(addrLen & 0xFF);
        int i = 16;
        foreach (byte b in src.GetAddressBytes()) o[i++] = b;
        foreach (byte b in dst.GetAddressBytes()) o[i++] = b;
        o[i++] = (byte)(srcPort >> 8); o[i++] = (byte)(srcPort & 0xFF);
        o[i++] = (byte)(dstPort >> 8); o[i] = (byte)(dstPort & 0xFF);
        return o;
    }

    static byte[] Hex(string s) => Convert.FromHexString(s);
    static byte[] Ascii(string s) => System.Text.Encoding.ASCII.GetBytes(s);

    static void Check(string name, string what, string got, string want)
    {
        if (got != want)
            Fail(name, $"{what}: got \"{got}\", want \"{want}\"");
    }

    static void Pass(string name) => Console.WriteLine("  ok    " + name);

    static void Fail(string name, string why)
    {
        _failures++;
        Console.WriteLine("  FAIL  " + name + ": " + why);
    }
}
