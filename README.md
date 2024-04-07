Sure, here's a sample README.md file for your network scanning tool:

---

# Network Scanner

This is a command-line network scanning tool developed in Python using the Scapy and Nmap libraries. It provides various scanning techniques to discover hosts, open ports, and detect network protocols.

## Features

- **ARP Scan:** Discovers devices in the local network using ARP requests.
- **TCP Scan:** Performs TCP port scanning using SYN packets and supports additional scanning techniques like Xmas, FIN, NULL, and ACK scans.
- **UDP Scan:** Conducts UDP port scanning to identify open ports.
- **ICMP Scan:** Performs ICMP echo ping, echo ping sweep, timestamp ping, and address mask ping scans.
- **IP Scan:** Detects supported IP protocols on a given host.

## Usage

Ensure you have Python installed on your system along with the required libraries listed in `requirements.txt`.

### Installation

```bash
pip install -r requirements.txt
```

### Usage Examples

1. **ARP Scan:**

```bash
python network_scanner.py ARP 192.168.1.0/24
```

2. **TCP Scan:**

```bash
python network_scanner.py TCP 192.168.1.1 22 80 --range
```

3. **UDP Scan:**

```bash
python network_scanner.py UDP 192.168.1.1 53 123 --range
```

4. **ICMP Scan:**

```bash
python network_scanner.py ICMP 192.168.1.1
```

5. **IP Scan:**

```bash
python network_scanner.py IP 192.168.1.1
```

For more details on usage and available options, refer to the help section of the tool.

## Disclaimer

This tool is intended for educational and ethical use only. Any unauthorized or malicious use of this tool is strictly prohibited. The developers are not responsible for any misuse of this tool.

---

Feel free to customize this README with additional information or instructions as needed.
