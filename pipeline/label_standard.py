"""Canonical Standard Family to MITRE ATT&CK Mapping (docs/23 section 2).

Standard reference mapping table for dataset standardisation.
Contains only the pre-approved attack families defined by the project.
New mappings or category adjustments must not be added here independently.
"""
from __future__ import annotations

import re
from typing import Any, Dict, Optional

# Canonical 14-column schema for ground_truth/<dataset>/events.csv / events.parquet
CANONICAL_EVENT_COLUMNS = [
    "campaign_id",
    "attacker_ip",
    "victim_ip",
    "dst_port",
    "start_ts",
    "end_ts",
    "attack_family",
    "attack_variant",
    "mitre_tactic",
    "mitre_technique",
    "label_source",
    "label_confidence",
    "original_label",
    "citation",
]

# Standard family to MITRE mapping table (docs/23 section 2)
# Family -> (MITRE Tactic ID, MITRE Technique ID, Kill-Chain Stage)
STANDARD_FAMILY_TABLE: Dict[str, Dict[str, str]] = {
    "portscan": {
        "attack_family": "portscan",
        "mitre_tactic": "TA0043",        # Reconnaissance (also TA0007 Discovery)
        "mitre_technique": "T1595",     # Active Scanning (also T1046)
        "kill_chain_stage": "reconnaissance",
    },
    "bruteforce": {
        "attack_family": "bruteforce",
        "mitre_tactic": "TA0006",        # Credential Access
        "mitre_technique": "T1110",     # Brute Force
        "kill_chain_stage": "initial_access",
    },
    "web_exploit": {
        "attack_family": "web_exploit",
        "mitre_tactic": "TA0001",        # Initial Access
        "mitre_technique": "T1190",     # Exploit Public-Facing Application
        "kill_chain_stage": "initial_access",
    },
    "infiltration": {
        "attack_family": "infiltration",
        "mitre_tactic": "TA0008",        # Lateral Movement
        "mitre_technique": "T1021",     # Remote Services
        "kill_chain_stage": "lateral_movement",
    },
    "botnet_c2": {
        "attack_family": "botnet_c2",
        "mitre_tactic": "TA0011",        # Command and Control
        "mitre_technique": "T1071",     # Application Layer Protocol
        "kill_chain_stage": "command_and_control",
    },
    "exfiltration": {
        "attack_family": "exfiltration",
        "mitre_tactic": "TA0010",        # Exfiltration
        "mitre_technique": "T1041",     # Exfiltration Over C2 Channel
        "kill_chain_stage": "exfiltration",
    },
    "dos": {
        "attack_family": "dos",
        "mitre_tactic": "TA0040",        # Impact
        "mitre_technique": "T1499",     # Endpoint Denial of Service
        "kill_chain_stage": "impact",
    },
    "ddos": {
        "attack_family": "ddos",
        "mitre_tactic": "TA0040",        # Impact
        "mitre_technique": "T1498",     # Network Denial of Service
        "kill_chain_stage": "impact",
    },
    "benign": {
        "attack_family": "benign",
        "mitre_tactic": "",
        "mitre_technique": "",
        "kill_chain_stage": "benign",
    },
}

# Mapping from common dataset raw category names to standard families
# ONLY includes direct synonyms documented in docs/23 section 5.
# Note: UNSW "reconnaissance" and "exploits" are deliberately omitted so Yash can decide them.
RAW_CATEGORY_TO_FAMILY: Dict[str, str] = {
    "benign": "benign",
    "normal": "benign",
    "portscan": "portscan",
    "port scan": "portscan",
    "ftp-patator": "bruteforce",
    "ssh-patator": "bruteforce",
    "ftp-bruteforce": "bruteforce",
    "ssh-bruteforce": "bruteforce",
    "brute force": "bruteforce",
    "web attack": "web_exploit",
    "web attack - brute force": "bruteforce",
    "web attack – brute force": "bruteforce",
    "web attack - xss": "web_exploit",
    "web attack – xss": "web_exploit",
    "web attack - sql injection": "web_exploit",
    "web attack – sql injection": "web_exploit",
    "heartbleed": "web_exploit",
    "infiltration": "infiltration",
    "infilteration": "infiltration",
    "bot": "botnet_c2",
    "botnet": "botnet_c2",
    "dos": "dos",
    "dos hulk": "dos",
    "dos goldeneye": "dos",
    "dos slowloris": "dos",
    "dos slowhttptest": "dos",
    "ddos": "ddos",
    "ddos attack-loic-http": "ddos",
    "ddos attacks-loic-http": "ddos",
    "ddos attack-loic-udp": "ddos",
    "ddos attacks-loic-udp": "ddos",
    "ddos attack-hoic": "ddos",
    "ddos attacks-hoic": "ddos",
    "dos attacks-goldeneye": "dos",
    "dos attacks-slowloris": "dos",
    "dos attacks-slowhttptest": "dos",
    "dos attacks-hulk": "dos",
    "dos-goldeneye": "dos",
    "dos-slowloris": "dos",
    "dos-slowhttptest": "dos",
    "dos-hulk": "dos",
    "ddos-loic-udp": "ddos",
    "ddos-hoic": "ddos",
    "ddos-loic-http": "ddos",
    "brute force -web": "bruteforce",
    "brute force -xss": "web_exploit",
    "sql injection": "web_exploit",
    "synth-exfiltration": "exfiltration",
}


def normalize_dashes(text: str) -> str:
    """Normalize hyphens, en-dashes, em-dashes, and Windows-1252 0x96 bytes to standard hyphen."""
    return text.replace("\x96", "-").replace("–", "-").replace("—", "-")


def lookup_standard_mapping(category: str) -> Optional[Dict[str, str]]:
    """Look up MITRE tactic and technique for a raw category name.
    
    Returns standard mapping dict if known, or None if unmapped.
    Normalises hyphens, en-dashes (U+2013), em-dashes, and 0x96 so either form matches.
    """
    if category is None:
        return None
    cleaned = category.strip().lower()
    family = RAW_CATEGORY_TO_FAMILY.get(cleaned)
    if not family:
        dash_norm = normalize_dashes(cleaned)
        family = RAW_CATEGORY_TO_FAMILY.get(dash_norm)
    if not family:
        family = cleaned if cleaned in STANDARD_FAMILY_TABLE else None
    if family and family in STANDARD_FAMILY_TABLE:
        return STANDARD_FAMILY_TABLE[family]
    return None
