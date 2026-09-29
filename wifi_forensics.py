#!/usr/bin/env python3
"""
wifi_forensics.py
==================

A WiFi forensics triage tool for Kismet-style .netxml capture logs.

Given a wireless capture exported from Kismet (.netxml), this tool:
  1. Parses every observed access point (network) and client.
  2. Summarizes each AP: SSID, BSSID, vendor, channel, encryption,
     signal strength, and the clients seen associated with it.
  3. Flags networks that look like rogue APs / evil twins using a simple
     heuristic: the same SSID broadcast from more than one BSSID, where
     at least one of those BSSIDs uses weaker or no encryption, or shows
     an anomalously strong signal relative to the others.
  4. Exports the findings as CSV and/or a clean PDF report suitable for
     inclusion in an incident write-up.

This is a standalone triage/analysis aid, not a full forensic suite: it
does not touch the original evidence file, and every finding it reports
should still be manually verified before being used as evidence.

Usage
-----
    python wifi_forensics.py sample_data/sample_capture.netxml
    python wifi_forensics.py sample_data/sample_capture.netxml --csv report.csv
    python wifi_forensics.py sample_data/sample_capture.netxml --pdf report.pdf

Author: Kamelisa Selami
"""

from __future__ import annotations

import argparse
import csv
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #

@dataclass
class Client:
    mac: str
    manuf: str
    first_seen: str
    last_seen: str


@dataclass
class AccessPoint:
    number: str
    ssid: str
    bssid: str
    manuf: str
    channel: str
    encryption: str
    max_signal_dbm: int | None
    last_signal_dbm: int | None
    first_seen: str
    last_seen: str
    packets: int
    clients: list[Client] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #

def _text(el: ET.Element | None, default: str = "") -> str:
    if el is None or el.text is None:
        return default
    return el.text.strip()


def _int(text: str) -> int | None:
    try:
        return int(float(text))
    except (TypeError, ValueError):
        return None


def parse_netxml(path: Path) -> list[AccessPoint]:
    """Parse a Kismet .netxml file into a list of AccessPoint records."""
    tree = ET.parse(path)
    root = tree.getroot()

    aps: list[AccessPoint] = []

    for net in root.findall("wireless-network"):
        ssid_el = net.find("SSID")
        essid_el = ssid_el.find("essid") if ssid_el is not None else None
        ssid = _text(essid_el, "<hidden/unknown>")
        encryption = _text(ssid_el.find("encryption")) if ssid_el is not None else ""
        packets = _int(_text(ssid_el.find("packets"))) if ssid_el is not None else 0

        snr = net.find("snr-info")
        max_signal = _int(_text(snr.find("max_signal_dbm"))) if snr is not None else None
        last_signal = _int(_text(snr.find("last_signal_dbm"))) if snr is not None else None

        ap = AccessPoint(
            number=net.attrib.get("number", "?"),
            ssid=ssid,
            bssid=_text(net.find("BSSID")),
            manuf=_text(net.find("manuf"), "Unknown"),
            channel=_text(net.find("channel")),
            encryption=encryption or "None",
            max_signal_dbm=max_signal,
            last_signal_dbm=last_signal,
            first_seen=net.attrib.get("first-time", ""),
            last_seen=net.attrib.get("last-time", ""),
            packets=packets or 0,
        )

        for client_el in net.findall("./client-list/wireless-client"):
            ap.clients.append(
                Client(
                    mac=_text(client_el.find("client-mac")),
                    manuf=_text(client_el.find("client-manuf"), "Unknown"),
                    first_seen=client_el.attrib.get("first-time", ""),
                    last_seen=client_el.attrib.get("last-time", ""),
                )
            )

        aps.append(ap)

    return aps


# --------------------------------------------------------------------------- #
# Rogue AP / evil-twin heuristic
# --------------------------------------------------------------------------- #

OPEN_ENCRYPTIONS = {"none", "open"}


@dataclass
class Finding:
    ssid: str
    suspicious_bssid: str
    reason: str
    legitimate_bssids: list[str]


def find_rogue_aps(aps: list[AccessPoint]) -> list[Finding]:
    """
    Flag SSIDs that are broadcast from more than one BSSID where the
    group's encryption or signal strength is inconsistent — a common
    signature of an evil-twin / rogue access point impersonating a
    known network.
    """
    by_ssid: dict[str, list[AccessPoint]] = {}
    for ap in aps:
        by_ssid.setdefault(ap.ssid, []).append(ap)

    findings: list[Finding] = []

    for ssid, group in by_ssid.items():
        if len(group) < 2 or ssid.startswith("<hidden"):
            continue

        encryptions = {ap.encryption.lower() for ap in group}
        signals = [ap.max_signal_dbm for ap in group if ap.max_signal_dbm is not None]

        # Mixed encryption within the same SSID: some APs secured, one isn't.
        if len(encryptions) > 1 and encryptions & OPEN_ENCRYPTIONS:
            strongest = max(group, key=lambda a: a.max_signal_dbm or -999)
            if strongest.encryption.lower() in OPEN_ENCRYPTIONS:
                others = [a.bssid for a in group if a.bssid != strongest.bssid]
                findings.append(
                    Finding(
                        ssid=ssid,
                        suspicious_bssid=strongest.bssid,
                        reason=(
                            f"broadcasts '{ssid}' with weaker/no encryption "
                            f"({strongest.encryption}) while other BSSIDs for the "
                            f"same SSID use stronger encryption"
                        ),
                        legitimate_bssids=others,
                    )
                )
                continue

        # Same SSID, same encryption class, but one BSSID is a clear signal
        # outlier (a rogue AP placed closer to victims to win the association).
        if len(signals) >= 2:
            strongest_signal = max(signals)
            weakest_signal = min(signals)
            if strongest_signal - weakest_signal >= 20:
                outlier = next(a for a in group if a.max_signal_dbm == strongest_signal)
                others = [a.bssid for a in group if a.bssid != outlier.bssid]
                findings.append(
                    Finding(
                        ssid=ssid,
                        suspicious_bssid=outlier.bssid,
                        reason=(
                            f"broadcasts '{ssid}' at {strongest_signal} dBm, "
                            f">=20 dB stronger than other BSSIDs for the same SSID "
                            f"({weakest_signal} dBm) — anomalous for a genuine second AP"
                        ),
                        legitimate_bssids=others,
                    )
                )

    return findings


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

def print_summary(aps: list[AccessPoint], findings: list[Finding]) -> None:
    print(f"\nParsed {len(aps)} network(s):\n")
    header = f"{'SSID':<20} {'BSSID':<18} {'Ch':<4} {'Enc':<8} {'Signal':<8} {'Clients':<7} Vendor"
    print(header)
    print("-" * len(header))
    for ap in aps:
        signal = f"{ap.max_signal_dbm}dBm" if ap.max_signal_dbm is not None else "n/a"
        print(
            f"{ap.ssid[:20]:<20} {ap.bssid:<18} {ap.channel:<4} "
            f"{ap.encryption[:8]:<8} {signal:<8} {len(ap.clients):<7} {ap.manuf}"
        )

    print(f"\n{len(findings)} potential rogue AP finding(s):\n")
    if not findings:
        print("  None detected by the current heuristic.")
    for f in findings:
        print(f"  [!] SSID '{f.ssid}' — BSSID {f.suspicious_bssid}")
        print(f"      Reason: {f.reason}")
        print(f"      Compare against known-good BSSID(s): {', '.join(f.legitimate_bssids)}\n")


def write_csv(aps: list[AccessPoint], out_path: Path) -> None:
    with out_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            ["ssid", "bssid", "manuf", "channel", "encryption",
             "max_signal_dbm", "last_signal_dbm", "packets",
             "first_seen", "last_seen", "client_count", "client_macs"]
        )
        for ap in aps:
            writer.writerow(
                [
                    ap.ssid, ap.bssid, ap.manuf, ap.channel, ap.encryption,
                    ap.max_signal_dbm, ap.last_signal_dbm, ap.packets,
                    ap.first_seen, ap.last_seen, len(ap.clients),
                    "; ".join(c.mac for c in ap.clients),
                ]
            )
    print(f"CSV report written to {out_path}")


def write_pdf(aps: list[AccessPoint], findings: list[Finding], source: Path, out_path: Path) -> None:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        )
    except ImportError:
        print(
            "PDF export needs the 'reportlab' package. Install it with:\n"
            "    pip install reportlab\n"
            "then re-run with --pdf.",
            file=sys.stderr,
        )
        sys.exit(1)

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "TitleNavy", parent=styles["Title"], textColor=colors.HexColor("#1F2D50")
    )
    heading_style = ParagraphStyle(
        "HeadingNavy", parent=styles["Heading2"], textColor=colors.HexColor("#1F2D50")
    )

    doc = SimpleDocTemplate(
        str(out_path), pagesize=A4,
        topMargin=2 * cm, bottomMargin=2 * cm, leftMargin=2 * cm, rightMargin=2 * cm,
    )
    story = [
        Paragraph("WiFi Forensics Report", title_style),
        Paragraph(f"Source capture: {source.name}", styles["Normal"]),
        Spacer(1, 0.6 * cm),
        Paragraph(f"Networks observed: {len(aps)}", styles["Normal"]),
        Paragraph(f"Potential rogue AP findings: {len(findings)}", styles["Normal"]),
        Spacer(1, 0.8 * cm),
        Paragraph("Observed Networks", heading_style),
        Spacer(1, 0.3 * cm),
    ]

    table_data = [["SSID", "BSSID", "Ch", "Encryption", "Max Signal", "Clients", "Vendor"]]
    for ap in aps:
        signal = f"{ap.max_signal_dbm} dBm" if ap.max_signal_dbm is not None else "n/a"
        table_data.append([ap.ssid, ap.bssid, ap.channel, ap.encryption, signal, str(len(ap.clients)), ap.manuf])

    table = Table(table_data, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F2D50")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D9D9D9")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F2F2F2")]),
            ]
        )
    )
    story.append(table)
    story.append(Spacer(1, 0.8 * cm))
    story.append(Paragraph("Rogue AP / Evil Twin Findings", heading_style))
    story.append(Spacer(1, 0.3 * cm))

    if not findings:
        story.append(Paragraph("None detected by the current heuristic.", styles["Normal"]))
    for f in findings:
        story.append(
            Paragraph(
                f"<b>SSID '{f.ssid}'</b> — suspicious BSSID {f.suspicious_bssid}",
                styles["Normal"],
            )
        )
        story.append(Paragraph(f"Reason: {f.reason}", styles["Normal"]))
        story.append(
            Paragraph(
                f"Compare against known-good BSSID(s): {', '.join(f.legitimate_bssids)}",
                styles["Normal"],
            )
        )
        story.append(Spacer(1, 0.4 * cm))

    doc.build(story)
    print(f"PDF report written to {out_path}")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main() -> None:
    parser = argparse.ArgumentParser(description="WiFi forensics triage tool for Kismet .netxml captures.")
    parser.add_argument("capture", type=Path, help="Path to a Kismet .netxml capture file")
    parser.add_argument("--csv", type=Path, metavar="PATH", help="Write a CSV report to PATH")
    parser.add_argument("--pdf", type=Path, metavar="PATH", help="Write a PDF report to PATH (requires reportlab)")
    args = parser.parse_args()

    if not args.capture.exists():
        print(f"Capture file not found: {args.capture}", file=sys.stderr)
        sys.exit(1)

    aps = parse_netxml(args.capture)
    findings = find_rogue_aps(aps)

    print_summary(aps, findings)

    if args.csv:
        write_csv(aps, args.csv)
    if args.pdf:
        write_pdf(aps, findings, args.capture, args.pdf)


if __name__ == "__main__":
    main()
