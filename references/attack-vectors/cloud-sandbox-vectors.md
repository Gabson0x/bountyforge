# Cloud Sandbox & Micro-Hypervisor Attack Vectors

Security vectors targeting platform-hosted sandbox environments, micro-VM hypervisors (Firecracker, gVisor, QEMU, Cloud Hypervisor), WASM runtimes, and guest-to-host boundaries.

---

## 1. Unauthenticated Guest-Side Daemon Listeners (CWE-306 / CWE-284)

### Mechanics
Platform-hosted sandboxes (Vercel Sandbox, AWS Lambda, Fly.io, Modal) deploy internal control daemons (`ControllerService`, `init.sock`, `agent.sock`) inside the guest network namespace to manage execution, file transfers, and output streaming.

### Attack Path
1. Workload process executes within the guest container/VM.
2. Attacker probes local interfaces (`127.0.0.1`, `0.0.0.0`, unix domain sockets `/run/*.sock`).
3. Connects directly over cleartext protocols (h2c, gRPC, HTTP, raw TCP) without presenting SDK credentials, API keys, or mTLS client certificates.
4. Issue raw `ExecCommand` or `CombinedOutputStream` RPCs to achieve arbitrary workload execution.

### Verification Checklist
- [ ] Scan local ports from guest (`ss -tulpn` or TCP connect scan to `127.0.0.1:1000-65535`).
- [ ] Inspect unix sockets (`ls -la /run/ /var/run/ /tmp/*.sock`).
- [ ] Test HTTP/2 prior knowledge (`h2c`) and gRPC reflection on listening ports.
- [ ] Construct **Absent Credential Evidence Grid** verifying zero auth headers present.

---

## 2. VSock Protocol Desync & Guest-Host Channel Abuse (CWE-419)

### Mechanics
Micro-VMs use Virtio-VSock (`AF_VSOCK`, CID 3 / 2) to communicate between host daemons and guest agents.

### Attack Surface
- **VSock Port Scanning:** Enumerate CID 2 (host) from guest using `socket(AF_VSOCK, SOCK_STREAM, 0)`.
- **Packet Framing Desync:** Send unexpected lengths, partial frames, or malformed protobuf headers over vsock to crash or trick host-side listener.
- **Multiplexing Confusion:** Overlap vsock stream IDs to hijack concurrent guest connections.

---

## 3. MicroVM MMDS Metadata Exploitation (CWE-918 / CWE-200)

### Mechanics
Firecracker MicroVM Metadata Service (MMDS) serves instance JSON at `169.254.169.254` over IPv4.

### Attack Vectors
- **Unauthenticated Metadata Access:** Query `http://169.254.169.254/` from guest process to retrieve host secrets, IAM tokens, or internal endpoints.
- **MMDS PUT Manipulation:** Send HTTP `PUT` requests to `169.254.169.254/user-data` if guest-side write permissions are improperly allowed.

---

## 4. WASM Linear Memory Bounds Bypass (CWE-119 / CWE-125)

### Mechanics
Sandboxes relying on WebAssembly (Wasmtime, Wasmer, V8) execute untrusted code in a shared linear memory space.

### Attack Vectors
- **Out-of-Bounds Indexing:** Exploit compiler gaps in Wasm bounds checks to read/write adjacent host-mapped memory buffers.
- **Host Function Abuse:** Abuse imported host functions (`env.import_fn`) to leak host pointers or invoke unvalidated host-side system capabilities.

---

## 5. Raw-Device & Block Layer Forensics (CWE-212 / CWE-226)

### Mechanics
Platform providers pool block images (`/dev/vda`, `/dev/sdb`) across guest VM instances to minimize cold-start latency.

### Attack Vectors
- **Uncleaned Block Residuals:** Read raw sectors from `/dev/vda` using `dd` or custom block parsers to recover previous tenant memory dumps, SSH keys, or unlinked environment files.
- **Kernel Symbol Reconstruction:** Scan `/dev/mem` or `/sys/kernel/notes` for unrandomized host kernel symbol offsets.
