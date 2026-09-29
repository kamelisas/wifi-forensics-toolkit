# WiFi Forensics Toolkit

A command-line tool for triaging Kismet-style `.netxml` wireless capture logs. It parses every access point and client seen in a capture, summarizes them, and flags networks that look like **rogue access points / evil twins** using a signal- and encryption-based heuristic — then exports the findings as CSV or a clean PDF report.

## Why

WiFi capture logs (from Kismet, or converted from Wireshark/airodump-ng captures) can contain hundreds of networks. Manually scanning a `.netxml` dump for a spoofed access point impersonating a trusted SSID is slow and error-prone. This tool automates the first triage pass: it surfaces exactly the networks worth a closer look, instead of requiring a full manual read-through.

## How the rogue-AP heuristic works

The same SSID is expected to come from one BSSID (or a small, consistent set of them, for multi-radio deployments). The tool flags a BSSID broadcasting a known SSID when either:

- **Encryption downgrade** — one BSSID uses weaker or no encryption while other BSSIDs for the same SSID are properly secured (a classic evil-twin signature: an attacker drops encryption to intercept traffic more easily).
- **Signal anomaly** — one BSSID is ≥20 dB stronger than the others broadcasting the same SSID, which is unusual for a genuine second access point and consistent with a rogue device placed deliberately close to victims to win the association race.

This is a triage heuristic, not a definitive detector — every flagged finding should still be manually verified before being treated as evidence.

## Usage

```bash
pip install -r requirements.txt

# Print a summary to the terminal
python wifi_forensics.py sample_data/sample_capture.netxml

# Also export a CSV
python wifi_forensics.py sample_data/sample_capture.netxml --csv report.csv

# Also export a PDF report
python wifi_forensics.py sample_data/sample_capture.netxml --pdf report.pdf
```

### Example output

```
Parsed 5 network(s):

SSID                 BSSID              Ch   Enc      Signal   Clients Vendor
-----------------------------------------------------------------------------
CampusNet-Staff      AA:11:22:33:44:01  36   WPA2     -46dBm   2       Cisco Systems
CampusNet-Student    AA:11:22:33:44:02  44   WPA2     -49dBm   1       Cisco Systems
CampusNet-Staff      AA:11:22:33:44:03  149  WPA2     -55dBm   0       Cisco Systems
CampusNet-Staff      DE:AD:BE:EF:00:99  6    None     -18dBm   1       Unknown
Eduroam              AA:11:22:33:44:05  1    WPA3     -60dBm   0       Aruba Networks

1 potential rogue AP finding(s):

  [!] SSID 'CampusNet-Staff' — BSSID DE:AD:BE:EF:00:99
      Reason: broadcasts 'CampusNet-Staff' with weaker/no encryption (None) while
      other BSSIDs for the same SSID use stronger encryption
      Compare against known-good BSSID(s): AA:11:22:33:44:01, AA:11:22:33:44:03
```

## Sample data

`sample_data/sample_capture.netxml` is a **synthetic** capture built to exercise the parser and the rogue-AP heuristic — it is not real captured traffic. It includes a planted "evil twin" (`CampusNet-Staff` broadcast from an unrelated BSSID with no encryption and an unusually strong signal) so the detection logic has something real to catch.

To use the tool on your own data, capture with Kismet and export a `.netxml` log, then point the tool at that file instead.

## Project structure

```
wifi-forensics-toolkit/
├── wifi_forensics.py       # CLI tool: parsing, heuristic, CSV/PDF export
├── requirements.txt
├── sample_data/
│   └── sample_capture.netxml
└── README.md
```

## Tech

Python 3.10+, standard library `xml.etree.ElementTree` for parsing (no parsing dependencies), [ReportLab](https://www.reportlab.com/) for PDF generation.

## Author

Kamelisa Selami — MSc Cybersecurity (CYBERUS), University of Luxembourg
