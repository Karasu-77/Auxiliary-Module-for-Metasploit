# Auxiliary module for Metasploit

### ping_checker.rb
An auxiliary module that verifies if one or more hosts are reachable via ICMP requests.

#### Features
- Single IP, range, and subnet scanning (e.g. `192.168.1.0/24`)
- Custom packet creation with personalized payload
- Latency metrics (min, avg, max)
- Jitter calculation
- Packet loss percentage
- TTL-based OS fingerprinting
- DNS resolution support (domains and IPs)
- Cross-platform support (Linux, macOS, Windows)
- Results saved to the Metasploit database

#### Technical Details
Since PacketFu 2.0.0 is incompatible with Ruby 3.4 (confirmed on both macOS and Ubuntu, affecting even official Metasploit modules like `arp_sweep` and `syn`), the module uses Ruby's native `Socket` library to:
- Build custom ICMP packets manually (`create_packet`)
- Calculate the checksum (`check_sum`)
- Send packets and capture replies via raw sockets (`send_packet`)

#### Installation
```bash
# create the module directory
mkdir -p ~/.msf4/modules/auxiliary/scanner/discovery/

# copy the module
cp ping_checker.rb ~/.msf4/modules/auxiliary/scanner/discovery/

# or symlink for live editing
ln -s /path/to/ping_checker.rb \
   ~/.msf4/modules/auxiliary/scanner/discovery/ping_checker.rb
```

#### Usage
```bash
sudo msfconsole
msf6 > use auxiliary/scanner/discovery/ping_checker
msf6 auxiliary(scanner/discovery/ping_checker) > set RHOSTS 8.8.8.8
msf6 auxiliary(scanner/discovery/ping_checker) > set COUNT 3
msf6 auxiliary(scanner/discovery/ping_checker) > set TIMEOUT 1
msf6 auxiliary(scanner/discovery/ping_checker) > set MESSAGE "Hello, World!"
msf6 auxiliary(scanner/discovery/ping_checker) > set THREADS 10
msf6 auxiliary(scanner/discovery/ping_checker) > run
```
