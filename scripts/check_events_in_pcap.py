"""Phase 4 - PCAP Event Validation Script (scripts/check_events_in_pcap.py).

Validates ground-truth events against raw packet captures (PCAP/PCAPNG).
Checks bidirectional communication between attacker and victim IPs,
searches within a configurable time window (default +/- 6 hours),
finds first and last packet timestamps, handles NAT mappings,
and computes time offsets from published event times.
"""
from __future__ import annotations

import argparse
import csv
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

CHECK_CSV_COLUMNS = [
    "campaign_id",
    "found",
    "first_pkt_utc",
    "last_pkt_utc",
    "offset_from_published_start",
    "observed_attacker_ip",
    "observed_victim_ip",
    "notes",
]

# Known NAT / gateway address mappings in datasets like CIC-IDS-2017
KNOWN_NAT_MAPPINGS: Dict[str, List[str]] = {
    "205.174.165.73": ["172.16.0.1"],
    "172.16.0.1": ["205.174.165.73"],
}


def parse_iso_utc(ts_str: str) -> Optional[datetime]:
    """Parse ISO UTC timestamp into datetime."""
    val = ts_str.strip()
    if not val:
        return None
    val = val.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(val)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def format_utc(dt: datetime) -> str:
    """Format datetime as UTC ISO 8601 ending in Z."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def find_tshark_path() -> Optional[str]:
    """Locate tshark binary."""
    which_path = shutil.which("tshark")
    if which_path:
        return which_path
    std = Path(r"C:\Program Files\Wireshark\tshark.exe")
    if std.exists():
        return str(std)
    std_x86 = Path(r"C:\Program Files (x86)\Wireshark\tshark.exe")
    if std_x86.exists():
        return str(std_x86)
    return None


def collect_pcap_files(target: Path) -> List[Path]:
    """Collect all PCAP and PCAPNG files from a path or directory."""
    if target.is_file():
        return [target]
    if not target.is_dir():
        return []
    exts = {".pcap", ".pcapng", ".cap"}
    out: List[Path] = []
    for root, _, files in os.walk(target):
        for f in files:
            p = Path(root) / f
            if p.suffix.lower() in exts:
                out.append(p)
    out.sort()
    return out


def scan_pcap_with_scapy(
    pcap_files: List[Path],
    candidate_attackers: set[str],
    candidate_victims: set[str],
    dst_port: Optional[int],
    start_dt: Optional[datetime],
    end_dt: Optional[datetime],
    window_seconds: float,
) -> Tuple[bool, Optional[float], Optional[float], Optional[str], Optional[str], str]:
    """Streaming packet scanner using Scapy PcapReader."""
    from scapy.all import IP, IPv6, PcapReader, TCP, UDP

    first_epoch: Optional[float] = None
    last_epoch: Optional[float] = None
    obs_att: Optional[str] = None
    obs_vic: Optional[str] = None
    pkt_count = 0
    scapy_notes: List[str] = []

    min_time = (start_dt.timestamp() - window_seconds) if start_dt else None
    max_time = (end_dt.timestamp() + window_seconds) if end_dt else None

    for pcap_file in pcap_files:
        try:
            with PcapReader(str(pcap_file)) as reader:
                for pkt in reader:
                    epoch = float(pkt.time)
                    if min_time is not None and epoch < min_time:
                        continue
                    if max_time is not None and epoch > max_time:
                        continue

                    sip, dip = None, None
                    if pkt.haslayer(IP):
                        sip = pkt[IP].src
                        dip = pkt[IP].dst
                    elif pkt.haslayer(IPv6):
                        sip = pkt[IPv6].src
                        dip = pkt[IPv6].dst
                    else:
                        continue

                    # Check endpoints in both directions
                    fwd = (sip in candidate_attackers) and (not candidate_victims or dip in candidate_victims)
                    rev = (dip in candidate_attackers) and (not candidate_victims or sip in candidate_victims)

                    if not (fwd or rev):
                        continue

                    if dst_port is not None:
                        dport = None
                        if pkt.haslayer(TCP):
                            dport = pkt[TCP].dport if fwd else pkt[TCP].sport
                        elif pkt.haslayer(UDP):
                            dport = pkt[UDP].dport if fwd else pkt[UDP].sport
                        if dport != dst_port:
                            continue

                    pkt_count += 1
                    if first_epoch is None or epoch < first_epoch:
                        first_epoch = epoch
                        if fwd:
                            obs_att, obs_vic = sip, dip
                        else:
                            obs_att, obs_vic = dip, sip

                    if last_epoch is None or epoch > last_epoch:
                        last_epoch = epoch

        except Exception as e:
            scapy_notes.append(f"scapy error reading {pcap_file.name}: {e}")

    if first_epoch is not None and last_epoch is not None:
        note = f"Matched {pkt_count} packets via streaming scan"
        if scapy_notes:
            note += f" ({'; '.join(scapy_notes)})"
        return True, first_epoch, last_epoch, obs_att, obs_vic, note

    note = "No matching packets found in window"
    if scapy_notes:
        note += f" ({'; '.join(scapy_notes)})"
    return False, None, None, None, None, note


def scan_pcap_with_tshark(
    pcap_files: List[Path],
    candidate_attackers: set[str],
    candidate_victims: set[str],
    dst_port: Optional[int],
    start_dt: Optional[datetime],
    end_dt: Optional[datetime],
    window_seconds: float,
    tshark_exe: str,
) -> Tuple[bool, Optional[float], Optional[float], Optional[str], Optional[str], str]:
    """Scan PCAP files using tshark for fast packet extraction."""
    first_epoch: Optional[float] = None
    last_epoch: Optional[float] = None
    obs_att: Optional[str] = None
    obs_vic: Optional[str] = None
    total_pkts = 0
    tshark_notes: List[str] = []

    min_time = (start_dt.timestamp() - window_seconds) if start_dt else None
    max_time = (end_dt.timestamp() + window_seconds) if end_dt else None

    # Build display filter
    ip_subfilters: List[str] = []
    for att in candidate_attackers:
        if candidate_victims:
            for vic in candidate_victims:
                ip_subfilters.append(f"(ip.src=={att} && ip.dst=={vic})")
                ip_subfilters.append(f"(ip.src=={vic} && ip.dst=={att})")
        else:
            ip_subfilters.append(f"(ip.src=={att} || ip.dst=={att})")

    filter_expr = " || ".join(ip_subfilters)
    if dst_port is not None:
        filter_expr = f"({filter_expr}) && (tcp.port=={dst_port} || udp.port=={dst_port})"

    for pcap in pcap_files:
        cmd = [
            tshark_exe,
            "-r", str(pcap),
            "-Y", filter_expr,
            "-T", "fields",
            "-e", "frame.time_epoch",
            "-e", "ip.src",
            "-e", "ip.dst",
        ]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if res.returncode != 0:
                err_msg = res.stderr.strip()[:100] if res.stderr else "unknown error"
                tshark_notes.append(f"tshark returned code {res.returncode}: {err_msg}")
                # Cut-short or truncated captures often return code 14 but still produce valid packets in stdout
                if not res.stdout or not res.stdout.strip():
                    continue

            for line in res.stdout.strip().splitlines():
                parts = line.strip().split()
                if len(parts) >= 3:
                    try:
                        ep = float(parts[0])
                        sip = parts[1]
                        dip = parts[2]
                        if min_time is not None and ep < min_time:
                            continue
                        if max_time is not None and ep > max_time:
                            continue

                        total_pkts += 1
                        if first_epoch is None or ep < first_epoch:
                            first_epoch = ep
                            if sip in candidate_attackers:
                                obs_att, obs_vic = sip, dip
                            else:
                                obs_att, obs_vic = dip, sip
                        if last_epoch is None or ep > last_epoch:
                            last_epoch = ep
                    except ValueError:
                        continue
        except Exception as exc:
            tshark_notes.append(f"tshark error on {pcap.name}: {exc}")
            continue

    if first_epoch is not None and last_epoch is not None:
        note = f"Matched {total_pkts} packets via tshark"
        if tshark_notes:
            note += f" ({'; '.join(tshark_notes)})"
        return True, first_epoch, last_epoch, obs_att, obs_vic, note

    note = "No matching packets found in window"
    if tshark_notes:
        note += f" ({'; '.join(tshark_notes)})"
    return False, None, None, None, None, note


def check_events_in_pcap(
    events_csv_path: Path | str,
    pcap_path: Path | str,
    out_csv_path: Path | str,
    window_hours: float = 6.0,
    prefer_scapy: bool = False,
) -> List[Dict[str, Any]]:
    """Validate each event in events_csv against the specified PCAP file or directory."""
    events_file = Path(events_csv_path).resolve()
    target_pcap = Path(pcap_path).resolve()
    out_file = Path(out_csv_path).resolve()

    if not events_file.is_file():
        raise FileNotFoundError(f"Events file {events_file} not found.")

    pcap_files = collect_pcap_files(target_pcap)
    tshark_exe = None if prefer_scapy else find_tshark_path()

    window_seconds = window_hours * 3600.0
    results: List[Dict[str, Any]] = []

    with open(events_file, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        events = list(reader)

    for ev in events:
        campaign_id = ev.get("campaign_id", "")
        att_ip = ev.get("attacker_ip", "").strip()
        vic_ip = ev.get("victim_ip", "").strip()
        dst_port_str = ev.get("dst_port", "").strip()
        start_ts_str = ev.get("start_ts", "").strip()
        end_ts_str = ev.get("end_ts", "").strip()

        start_dt = parse_iso_utc(start_ts_str)
        end_dt = parse_iso_utc(end_ts_str) or start_dt

        dst_port = int(dst_port_str) if dst_port_str.isdigit() else None

        cand_att = {att_ip} if att_ip else set()
        if att_ip in KNOWN_NAT_MAPPINGS:
            cand_att.update(KNOWN_NAT_MAPPINGS[att_ip])

        cand_vic = {vic_ip} if vic_ip else set()
        if vic_ip in KNOWN_NAT_MAPPINGS:
            cand_vic.update(KNOWN_NAT_MAPPINGS[vic_ip])

        if not pcap_files:
            results.append({
                "campaign_id": campaign_id,
                "found": "no",
                "first_pkt_utc": "",
                "last_pkt_utc": "",
                "offset_from_published_start": "",
                "observed_attacker_ip": "",
                "observed_victim_ip": "",
                "notes": f"PCAP path {target_pcap} contains no capture files",
            })
            continue

        if tshark_exe:
            found, f_epoch, l_epoch, o_att, o_vic, note = scan_pcap_with_tshark(
                pcap_files, cand_att, cand_vic, dst_port, start_dt, end_dt, window_seconds, tshark_exe
            )
        else:
            found, f_epoch, l_epoch, o_att, o_vic, note = scan_pcap_with_scapy(
                pcap_files, cand_att, cand_vic, dst_port, start_dt, end_dt, window_seconds
            )

        if found and f_epoch is not None and l_epoch is not None:
            f_dt = datetime.fromtimestamp(f_epoch, tz=timezone.utc)
            l_dt = datetime.fromtimestamp(l_epoch, tz=timezone.utc)
            first_utc_str = format_utc(f_dt)
            last_utc_str = format_utc(l_dt)

            offset_sec = ""
            if start_dt:
                offset_sec = f"{(f_epoch - start_dt.timestamp()):.2f}"

            results.append({
                "campaign_id": campaign_id,
                "found": "yes",
                "first_pkt_utc": first_utc_str,
                "last_pkt_utc": last_utc_str,
                "offset_from_published_start": offset_sec,
                "observed_attacker_ip": o_att or "",
                "observed_victim_ip": o_vic or "",
                "notes": note,
            })
        else:
            results.append({
                "campaign_id": campaign_id,
                "found": "no",
                "first_pkt_utc": "",
                "last_pkt_utc": "",
                "offset_from_published_start": "",
                "observed_attacker_ip": "",
                "observed_victim_ip": "",
                "notes": note,
            })

    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CHECK_CSV_COLUMNS)
        writer.writeheader()
        for r in results:
            writer.writerow(r)

    print(f"\n[check_events_in_pcap] Checked {len(events)} events against {len(pcap_files)} capture files.")
    found_count = sum(1 for r in results if r["found"] == "yes")
    print(f"Results written to {out_file}: {found_count}/{len(events)} events found in capture.\n")
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Check and validate ground-truth events in PCAP captures.")
    parser.add_argument("--events", required=True, help="Path to events.csv (e.g. ground_truth/cic2017/events.csv)")
    parser.add_argument("--pcap", required=True, help="Path to a PCAP file or directory containing PCAP files")
    parser.add_argument("--out", required=True, help="Output check.csv path")
    parser.add_argument("--window-hours", type=float, default=6.0, help="Search window in hours around event time (default 6.0)")
    parser.add_argument("--scapy-only", action="store_true", help="Force pure Python Scapy scanner without tshark")

    args = parser.parse_args()
    check_events_in_pcap(
        events_csv_path=args.events,
        pcap_path=args.pcap,
        out_csv_path=args.out,
        window_hours=args.window_hours,
        prefer_scapy=args.scapy_only,
    )


if __name__ == "__main__":
    main()

