# XDPLB (eBPF XDP Load Balancer)
XDPLB is a high-performance Layer 4 Load Balancer built on eBPF (Extended Berkeley Packet Filter) and XDP (eXpress Data Path) technology.

It implements the DSR (Direct Server Return) pattern, processing packets at the earliest possible point in the network driver stack (XDP_DRV or XDP_SKB). By modifying only the L2 Destination MAC address and reflecting the packet back via XDP_TX, it achieves ultra-low latency and high throughput.

![Language](https://img.shields.io/badge/Language-C-00599C?style=flat&logo=c&logoColor=white)
![Tech](https://img.shields.io/badge/Technology-eBPF%20%7C%20XDP-orange?style=flat&logo=linux&logoColor=white)
![Kernel](https://img.shields.io/badge/Kernel-5.14+-red?style=flat&logo=linux&logoColor=white)
![Compiler](https://img.shields.io/badge/Compiler-Clang%20%2F%20LLVM-181717?style=flat&logo=llvm&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey?style=flat&logo=linux&logoColor=white)
![License](https://img.shields.io/badge/License-Apache%202.0-blue?style=flat&logo=apache&logoColor=white)
![Repo Size](https://img.shields.io/github/repo-size/hoon-x/xdplb?style=flat&color=success)
![Last Commit](https://img.shields.io/github/last-commit/hoon-x/xdplb?style=flat&color=blueviolet)
![Issues](https://img.shields.io/github/issues/hoon-x/xdplb?style=flat)

## Demo
Real-time traffic monitoring dashboard in debug mode.
<p align="center">
  <img src="./docs/images/demo.gif" width="1000"/>
  <br>
</p>

## Key Features
- **Kernel Bypass Performance**: Processes packets directly in the network driver hook, avoiding the overhead of the kernel network stack (sk_buff allocation).
- **Layer 4 Load Balancing**: Supports TCP and UDP traffic distribution based on 5-Tuple hashing.
- **Direct Server Return (DSR)**:
    - **Ingress**: Processed by XDPLB.
    - **Egress**: Real Servers reply directly to the client, bypassing the LB for return traffic.
- **Operational Management**:
    - **CLI Control**: Simple start, stop, and debug commands.
    - **Daemonization**: Runs as a background system process with PID management.
    - **Signal Handling**: Graceful shutdown on SIGTERM/SIGINT.
- **Dynamic Configuration**: JSON-based configuration for managing VIPs and Real Servers.
- **Observability**:
    - Real-time TUI dashboard (Packets/Bytes per VIP).
    - Detailed logging via syslog and file logs.

## Architecture
XDPLB operates as a "One-Armed" Load Balancer using the XDP_TX action.


1. **Packet Parsing**: XDP program parses Ethernet, IPv4, and TCP/UDP headers.
2. **VIP Lookup**: Checks if the packet's destination IP/Port matches a configured VIP.
3. **Hashing**: Calculates a 32-bit Jenkins Hash using the packet's 5-Tuple (SrcIP, DstIP, SrcPort, DstPort, Proto).
4. **Server Selection**: Selects a Real Server using Hash % Real_Count (Round Robin distribution).
5. **L2 Rewrite**:
    - Updates Destination MAC to the selected Real Server's MAC.
    - Updates Source MAC to the LB interface's MAC.
6. **Forwarding**: Transmits the modified packet out of the same interface (XDP_TX).

## Prerequisites
- **OS**: Linux Kernel 5.14 or higher (Compatible with **Rocky Linux 9 / RHEL 9**).
    - *Note: Primary testing and verification were conducted on **Rocky Linux 10 (Kernel 6.12)**.*
- **Dependencies**:
    - libbpf
    - clang / llvm
    - make
    - bpftool

## Installation
```bash
# 1. Clone the repository
git clone [https://github.com/hoon-x/xdplb.git](https://github.com/hoon-x/xdplb.git)
cd xdplb

# 2. Build (Compiles both BPF object and User-space binary)
make

# 3. Verify binary
ls -l bin/xdplb
```

## Configuration
Create a lb_conf.json file. You can define multiple VIPs and multiple Real Servers per VIP.
- **Important**: Do not include your SSH management port (e.g., 22) in the configuration.
```json
{
  "vips": [
    {
      "vip": "192.168.75.105",   // LB Interface IP (VIP)
      "port": 8080,              // Service Port
      "protocol": "tcp",         // "tcp" or "udp"
      "reals": [
        {
          "ip": "192.168.75.18",     // Real Server 1 IP
          "mac": "00:0c:29:36:09:78" // Real Server 1 MAC
        },
        {
          "ip": "192.168.75.92",     // Real Server 2 IP
          "mac": "00:0c:29:10:5b:36" // Real Server 2 MAC
        }
      ]
    }
  ]
}
```

## Usage
The binary provides a CLI interface for managing the load balancer service.

### Start Daemon
Runs XDPLB in the background. Logs are written to syslog and the log file.
```bash
sudo ./bin/xdplb start -i ens160
```

### Debug Mode (Foreground)
Runs in the foreground with a real-time statistics dashboard.
```bash
sudo ./bin/xdplb debug -i ens160
```

### Stop Daemon
Sends a SIGTERM signal to the running background process.
```bash
sudo ./bin/xdplb stop
```

## Real Server Setup (DSR Requirement)
For DSR to work, Real Servers must accept packets destined for the VIP but respond using their own IP address.

Run this on ALL Real Servers:
```bash
# 1. ARP Suppression (Prevent RS from answering ARP for VIP)
sudo sysctl -w net.ipv4.conf.all.arp_ignore=1
sudo sysctl -w net.ipv4.conf.eth0.arp_ignore=1
sudo sysctl -w net.ipv4.conf.all.arp_announce=2
sudo sysctl -w net.ipv4.conf.eth0.arp_announce=2

# 2. Loopback Alias (Assign VIP to lo interface)
# Replace 192.168.75.105 with your VIP
sudo ip addr add 192.168.75.105/32 dev lo label lo:0
```

## License
Copyright 2026 JongHoon Shim.

Licensed under the Apache License, Version 2.0. See LICENSE for details.
