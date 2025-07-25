# Python Network Sniffer

A simple but effective network packet sniffer built in Python using the Scapy library. This tool captures and displays detailed information about network traffic on your local network interface, making it an excellent utility for network analysis, debugging, and educational purposes.

## Features

* **Live Packet Capture:** Captures network packets in real-time.

* # **Multi-Layer Analysis:** Dissects and displays information from different network layers:

  * **Link Layer (Ethernet):** Shows source and destination MAC addresses.

  * **Network Layer (IP):** Shows source and destination IP addresses and the protocol being used (TCP, UDP, ICMP, etc.).

  * **Transport Layer (TCP/UDP):** Displays source and destination ports.

* **Payload Inspection:** Shows the raw data payload of TCP/UDP packets in a readable hexdump format.

* **Cross-Platform:** Runs on any system with Python and Scapy installed (Linux, macOS, Windows).

* **Lightweight & Readable:** The script is well-commented and easy to understand, making it ideal for learning.

## Requirements

* Python 3.x

* `scapy` library

## Installation

1. **Clone the repository or download the `network_sniffer.py` script.**

2. **Install the `scapy` library using pip:**

   ```
   pip install scapy
   ```

## Usage

This script requires low-level access to the network interface card to capture packets. Therefore, you **must** run it with root or administrator privileges.

**On Linux or macOS:**

```
sudo python3 network_sniffer.py
```

**On Windows:**

Open a Command Prompt or PowerShell **as an Administrator** and run:

```
python network_sniffer.py
```

Once running, the sniffer will immediately start capturing packets. Press `Ctrl+C` to stop the program.

### Example Output

```
Starting network sniffer...
Press Ctrl+C to stop.

[+] New Packet: 01:00:5e:00:00:fb -> 3c:e9:f7:b4:a1:c2
    [IP] 192.168.1.10 -> 239.255.255.250 | Protocol: UDP
        [UDP] Source Port: 61658 -> Destination Port: 1900
        [Payload] Data:
0000  4D 2D 53 45 41 52 43 48 20 2A 20 48 54 54 50 2F M-SEARCH * HTTP/
0010  31 2E 31 0D 0A 48 6F 73 74 3A 20 32 33 39 2E 32 1.1..Host: 239.2
0020  35 35 2E 32 35 35 2E 32 35 30 3A 31 39 30 30 0D 55.255.250:1900.
0030  0A 4D 41 4E 3A 20 22 73 73 64 70 3A 64 69 73 63 .MAN: "ssdp:disc
0040  6F 76 65 72 22 0D 0A 4D 58 3A 20 33 0D 0A 53 54 over"..MX: 3..ST
0050  3A 20 75 72 6E 3A 73 63 68 65 6D 61 73 2D 75 70 : urn:schemas-up
0060  6E 70 2D 6F 72 67 3A 64 65 76 69 63 65 3A 4D 65 np-org:device:Me
0070  64 69 61 52 65 6E 64 65 72 65 72 3A 31 0D 0A 0D diaRenderer:1...
0080  0A                                             .

[+] New Packet: 3c:e9:f7:b4:a1:c2 -> 0a:05:01:0a:ff:1a
    [IP] 192.168.1.10 -> 8.8.8.8 | Protocol: TCP
        [TCP] Source Port: 54321 -> Destination Port: 443
        [Payload] Data:
0000  17 03 03 00 5c 00 00 00 00 00 00 00 00 1a 7a 8b ....\\.........z.
...
```

## How It Works

The script uses the `sniff` function from the Scapy library to capture all packets. For each packet captured, it calls the `packet_callback` function. This function checks for the presence of different protocol layers (Ether, IP, TCP, UDP) and extracts the relevant information to print to the console.

## Disclaimer

This tool is intended for educational and legitimate network monitoring purposes only. Using a network sniffer to capture data on a network you do not own or have permission to monitor is illegal. Please use this tool responsibly.
