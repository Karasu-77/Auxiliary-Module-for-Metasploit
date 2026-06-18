# Auxiliary module for Metasploit

### ping_checker.rb
An auxiliary module that verifies if one or more hosts are reachable via ICMP requests.

#### Features
- Single IP, range, and subnet scanning (e.g. `192.168.1.0/24`);
- Custom packet creation with personalized payload;
- Latency metrics (min, avg, max);
- Jitter calculation;
- Packet loss percentage;
- DNS resolution support (domains and IPs);
- Cross-platform support (Linux, MacOS, Windows);
- Results saved to the Metasploit database;


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

```

#### Usage

RHOSTS - target IP, range, or subnet
COUNT - number of packets to send
TIMEOUT - timeout between packets (in seconds)
MESSAGE - hello | Custom payload message
THREADS - number of parallel threads

```bash

sudo msfconsole

msf6 > loadpath ~/.msf4/modules
msf6 > use auxiliary/scanner/discovery/ping_checker
msf6 auxiliary(scanner/discovery/ping_checker) > set RHOSTS 8.8.8.8 192.168.1.0/24
msf6 auxiliary(scanner/discovery/ping_checker) > set COUNT 3
msf6 auxiliary(scanner/discovery/ping_checker) > set TIMEOUT 1
msf6 auxiliary(scanner/discovery/ping_checker) > set MESSAGE "hello, world!"
msf6 auxiliary(scanner/discovery/ping_checker) > set THREADS 10
msf6 auxiliary(scanner/discovery/ping_checker) > run

```
