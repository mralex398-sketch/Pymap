# Pymap - Advanced Multi-Engine Network Scanner

Pymap is a modular, high-performance network reconnaissance and port auditing tool written in Python 3. Engineered for penetration testers and network administrators, it features an asynchronous multi-threaded architecture capable of bypassing modern firewall defensive mechanisms such as network tarpits, dynamic port spoofing, and SSL/TLS validation hurdles.

---

## ✨ Core Features

- **🚀 Hybrid Concurrency Core**: Driven by Python’s thread-safe `queue.Queue` engine to spin up massive parallel worker pools, optimizing scan rates across exhaustive port ranges.
- **🛡️ Intelligent Tarpit & Spoofing Evasion**: Proactively evaluates ephemeral target responses before initiating the scan. If a honeypot or *Portspoof* decoy environment is flagged, Pymap auto-adapts to prevent scanner locking.
- **🔍 Deep Verification (Strict Banner Grabbing)**: Validates actual service reachability by processing raw byte handshakes (`SERVICE_PROBES`), successfully filtering out fake firewall "open" indications.
- **🔒 Dynamic SSL/TLS Handling & SNI**: Seamlessly encapsulates raw sockets into cryptographic contexts using Python's `ssl` layer when targeting HTTPS nodes, preserving Server Name Indication (SNI).
- **🎛️ Three Independent Scanning Engines**:
  - `banner`: Asynchronous built-in native TCP Connect scan with smart service checking.
  - `nmap`: Harnesses a local host `nmap` installation out-of-the-box using safe `subprocess` abstractions.
  - `syn`: Runs stealthy raw packet stealth SYN scanning via Scapy integration.

---

## 📋 Requirements & Installation

While the base `banner` scanning mode utilizes native Python standard modules, advanced engines require dependencies:

1. Clone this repository into your chosen workspace folder:
```bash
git clone https://github.com
cd Pymap
```

2. If you intend to use the raw packet Stealth SYN mode, install Scapy:
```bash
pip install scapy
```
*Note: SYN scan operations manipulate raw network interfaces and require root/administrator system privileges.*

3. If you intend to use the Nmap engine, verify Nmap is available in your environment's PATH:
```bash
# Debian / Ubuntu / Kali / Parrot
sudo apt install nmap
```

---

## 🚀 Execution & Options

Run the utility from your preferred command-line shell interface:

```bash
python Pymap.py <target> [options]
```

### Argument Matrix:


| Flag | Parameter Type | Functional Overview | Default |
| :--- | :--- | :--- | :--- |
| `target` | `String` | Target domain name or destination IP address | *Required* |
| `-p`, `--ports` | `String` | Target port matrix (e.g., `80,443` or a range `1-1024`) | `1-1024` |
| `-t`, `--threads` | `Integer` | Max simultaneous runtime thread limits | `50` |
| `--timeout` | `Float` | Connection timing drop threshold in seconds | `1.0` |
| `--mode` | `Choice` | The scanner engine selection (`banner`, `nmap`, `syn`) | `banner` |
| `--strict` | `Flag` | Enforces deep byte validation on every responder | `False` |
| `--retries` | `Integer` | Connection attempt fallback index count per port | `2` |

### Command Examples:

```bash
# Standard Network Audit against an explicit port block
python Pymap.py 192.168.1.1 -p 21,22,80,443 --threads 20

# Strict verification against heavily firewalled target infrastructure
python Pymap.py example.com -p 1-5000 --strict --timeout 0.5

# Execution via the low-level stealth SYN packet engine
sudo python Pymap.py 10.10.10.15 --mode syn -p 1-1024
```

---

## ⚖️ Legal & Educational Disclaimer

**IMPORTANT NOTICE:** This software is engineered strictly for authorized security evaluations, educational vulnerability tracking, and defensive network posture validation. 

Running aggressive automated mapping tools against unauthorized external production endpoints without explicitly documented, written confirmation from the asset owner is entirely illegal. The author holds **no liability** for any operational friction, firewall alerts, or regulatory enforcement actions caused by the misuse of this implementation.
