# Project Specification: Lightweight AnyTLS Transparent MITM Proxy for Windows Hotspot

## 1. Role & Objective
You are an expert Go systems and network engineer. Build a lightweight, transparent Man-in-the-Middle (MITM) proxy in **Go (Golang)** running on a **Windows host with Mobile Hotspot enabled**. 

The goal is strictly limited to:
1. Transparently intercepting TCP traffic coming from client devices connected to the Windows Hotspot (default ICS subnet `192.168.137.0/24`).
2. Executing a 3-stage pipeline to accurately identify `anytls` protocol connections that have `skip-cert-verify: true` enabled and establishing an active MITM session.
3. **No Deep Packet Inspection or Data Storage**: Once an `anytls` connection is identified and MITM'd, simply log the detection event (Client IP, Server IP, Outer SNI, and the 32-byte Auth Hash) and transparently bridge (`io.Copy`) the two TLS streams. Do NOT parse inner frames, do NOT extract inner payloads, and do NOT save any traffic content to disk.

---

## 2. Windows Hotspot Interception Mechanism (WinDivert + NAT Table)

When Windows Mobile Hotspot is turned on, Windows creates a virtual adapter (usually `192.168.137.1`) and routes traffic from connected devices (`192.168.137.2` - `192.168.137.254`).

Use **WinDivert** (`github.com/williamfhe/godivert` or `github.com/imgk/divert-go`) to transparently redirect hotspot client TCP traffic to a local Go TCP listener (e.g., `192.168.137.1:10443`):

1. **WinDivert Filter**:
   - Intercept traffic between the hotspot subnet (`192.168.137.0/24`) and external servers on target TCP ports (default `443`, configurable via CLI flags).
   - Maintain a thread-safe in-memory NAT mapping table: `map[ClientIPPort]OriginalDstIPPort`.
2. **Packet Redirection**:
   - **Inbound from Hotspot Client** (`SrcIP` in `192.168.137.0/24` and `DstPort == 443`): Record `ClientIP:ClientPort -> OriginalDstIP:OriginalDstPort` in the NAT table. Rewrite `DstIP` to `192.168.137.1` and `DstPort` to `10443`, recalculate checksums, and re-inject.
   - **Outbound from Local Listener** (`SrcIP == 192.168.137.1` and `SrcPort == 10443`): Look up the original destination from the NAT table using `DstIP:DstPort` (the client), rewrite `SrcIP` and `SrcPort` back to `OriginalDstIP:OriginalDstPort`, recalculate checksums, and re-inject.

---

## 3. Three-Stage AnyTLS Identification & MITM Pipeline

When the local TCP listener (`192.168.137.1:10443`) accepts a connection from a hotspot client, look up `OriginalDstIP:Port` from the NAT table and execute these 3 stages:

### Stage 1: Fail-Open Whitelist & Pre-Handshake Check
To prevent breaking normal HTTPS browsing on the hotspot client:
1. **Strict-TLS Whitelist Check**:
   - Check an in-memory TTL cache (`WhitelistCache`, TTL = 30 minutes) for `OriginalDstIP:Port`.
   - If found, immediately dial raw TCP to `OriginalDstIP:Port` and splice the raw TCP connections (`io.Copy`) without touching TLS.
2. **ClientHello Verification**:
   - Wrap the client TCP connection in a `bufio.Reader` and `Peek(5)`.
   - Verify it is a TLS Record (`buf[0] == 0x16`). If not, fallback to raw TCP splice immediately.

### Stage 2: Dynamic Certificate Cloning & Handshake Probing
1. **Upstream TLS Connection**:
   - Inside `tls.Config.GetConfigForClient`, dial `OriginalDstIP:Port` using `crypto/tls` with `InsecureSkipVerify: true`, forwarding the client's `ServerName` (SNI) and `SupportedProtos` (ALPN).
2. **1:1 Certificate Cloning**:
   - Grab `PeerCertificates[0]` from the upstream TLS connection.
   - Generate a cloned X.509 certificate in memory: copy `Subject`, `Issuer`, `DNSNames`, `IPAddresses`, `NotBefore`, and `NotAfter` from the upstream cert, and sign it using a local in-memory ECDSA P-256 private key. (Cache cloned certs by `OriginalDstIP:Port`).
3. **Downstream TLS Handshake & Fail-Open Recovery**:
   - Complete the `tls.Server` handshake with the hotspot client using the cloned certificate.
   - **Crucial Fail-Open Logic**: If `clientTLS.Handshake()` returns an error (e.g., `tls: bad certificate` because the client is a standard browser or has `skip-cert-verify: false`):
     - Immediately add `OriginalDstIP:Port` to `WhitelistCache`.
     - Close both connections. When the client automatically retries in a few milliseconds, Stage 1 will bypass MITM and forward raw TCP seamlessly.

### Stage 3: First-Packet AnyTLS Identification & Transparent Relay
If the TLS handshake succeeds, the client has accepted our forged certificate (`skip-cert-verify: true`). Now verify if the decrypted stream is `anytls`:

1. **Non-Destructive First-Packet Inspection**:
   - Wrap `clientTLS` in `br := bufio.NewReaderSize(clientTLS, 65536)`.
   - According to the `anytls-go` protocol specification, the first packet layout is:
     `[SHA256(password) : 32B] + [Padding0_Len (L0) : 2B Big-Endian] + [Padding0 : L0 Bytes] + [Frame Header : 7B]`
     Where the 7-byte Frame Header is: `[Cmd : 1B] + [StreamID : 4B Big-Endian] + [DataLen : 2B Big-Endian]`.
2. **Identification Rule**:
   - `Peek(34)` bytes from `br`.
   - Reject obvious HTTP plaintext prefixes (`GET `, `POST `, `HEAD `, `PRI * HTTP/2.0`).
   - Read `L0 := int(binary.BigEndian.Uint16(buf[32:34]))`.
   - Set `offset := 34 + L0`.
   - `Peek(offset + 7)` bytes from `br`.
   - Read `cmd := buf[offset]` and `streamID := binary.BigEndian.Uint32(buf[offset+1 : offset+5])`.
   - **Match Condition**: In `anytls`, the very first frame after `padding0` is always `cmdSettings` (`cmd == 4` and `streamID == 0`), `cmdWaste` (`cmd == 0` and `streamID == 0`), or `cmdSYN` (`cmd == 1`).
3. **Log & Transparent Relay (No Data Saving)**:
   - If matched:
     - Log a console message: `[ANYTLS-MITM-SUCCESS] Client: <IP> -> Server: <IP:Port> | SNI: <SNI> | AuthHash(SHA256): <hex_of_first_32_bytes>`.
   - If not matched:
     - Log `[NON-ANYTLS-MITM] Client: <IP> -> Server: <IP:Port> (Forwarding transparently)`.
   - **In both cases**: Do NOT inspect or store subsequent bytes. Immediately bridge the decrypted streams in two goroutines using `io.Copy(upstreamTLS, br)` and `io.Copy(clientTLS, upstreamTLS)` so the connection functions normally through our MITM tunnel.

---

## 4. Expected Project Structure

Keep the codebase minimal, clean, and easy to compile on Windows:

```text
anytls-hotspot-mitm/
├── go.mod
├── main.go             # CLI flags (-subnet, -listen-ip, -ports), Admin check, startup
├── divert/
│   ├── redirector.go   # WinDivert packet loop & TCP NAT redirection for hotspot subnet
│   └── nat.go          # Thread-safe NAT mapping table
└── mitm/
    ├── proxy.go        # TCP listener & Stage 1-3 pipeline implementation
    ├── cert.go         # In-memory ECDSA key & 1:1 X.509 certificate cloner
    ├── whitelist.go    # TTL cache for strict-verify servers (Fail-Open)
    └── detector.go     # Stage 3 AnyTLS first-packet binary inspector
```

## 5. Instructions for Antigravity

1. Initialize the Go module and implement all files completely without placeholders or `TODO`s.
2. Add a build or run guide in a brief `README.md` explaining where to place `WinDivert.dll` and `WinDivert64.sys` and how to run the binary as Administrator after enabling Windows Mobile Hotspot.
3. Write a unit test in `mitm/detector_test.go` to verify that `inspectAnyTLSFirstPacket` correctly identifies simulated `anytls` initial packets (with various `Padding0` lengths) and rejects standard HTTP/1.1 or HTTP/2 streams.