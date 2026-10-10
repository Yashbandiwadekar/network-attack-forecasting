"""Maps CIC-IDS-2018 and CTU-13 labels to MITRE-style attack stages.

The internal pipeline uses five attack stages:
- reconnaissance
- initial_access
- lateral_movement
- command_and_control
- exfiltration

Benign traffic is also kept as a classification class.

CTU-13 does not provide labels that map perfectly to all five stages.
Therefore, the mapping is deliberately conservative.

Unknown labels are mapped to IMPACT instead of silently becoming benign.
"""

from __future__ import annotations

import logging

_log = logging.getLogger(__name__)
_WARNED_CTU13_LABELS: set[str] = set()


# ---------------------------------------------------------------------------
# Internal stage names
# ---------------------------------------------------------------------------

BENIGN = "benign"
RECONNAISSANCE = "reconnaissance"
INITIAL_ACCESS = "initial_access"
LATERAL_MOVEMENT = "lateral_movement"
COMMAND_AND_CONTROL = "command_and_control"
EXFILTRATION = "exfiltration"

# CTU-13 / CIC labels that do not belong to the requested five-stage
# classification head.
IMPACT = "impact"


# ---------------------------------------------------------------------------
# Classification labels used by the model
# ---------------------------------------------------------------------------

STAGE_CLASSIFICATION_LABELS = [
    BENIGN,
    RECONNAISSANCE,
    INITIAL_ACCESS,
    LATERAL_MOVEMENT,
    COMMAND_AND_CONTROL,
    EXFILTRATION,
]


# ---------------------------------------------------------------------------
# CIC-IDS-2018 label mapping
# ---------------------------------------------------------------------------

CIC_LABEL_TO_STAGE: dict[str, str] = {
    # Benign
    "BENIGN": BENIGN,
    "Benign": BENIGN,

    # Initial Access
    "FTP-BruteForce": INITIAL_ACCESS,
    "SSH-Bruteforce": INITIAL_ACCESS,
    "Brute Force -Web": INITIAL_ACCESS,
    "Brute Force -XSS": INITIAL_ACCESS,
    "SQL Injection": INITIAL_ACCESS,

    # Lateral Movement
    "Infilteration": LATERAL_MOVEMENT,
    "Infiltration": LATERAL_MOVEMENT,

    # Command and Control
    "Bot": COMMAND_AND_CONTROL,

    # Impact
    "DoS attacks-GoldenEye": IMPACT,
    "DoS attacks-Slowloris": IMPACT,
    "DoS attacks-SlowHTTPTest": IMPACT,
    "DoS attacks-Hulk": IMPACT,
    "DDOS attack-HOIC": IMPACT,
    "DDOS attack-LOIC-UDP": IMPACT,
    "DDoS attacks-LOIC-HTTP": IMPACT,

    # Synthetic-only label used by the project.
    "SYNTH-Exfiltration": EXFILTRATION,
}

# ---------------------------------------------------------------------------
# CIC-IDS-2017 labels (additive; CIC-2018 entries above are unchanged).
# Web-attack labels contain a Windows-1252 en-dash in the released CSVs
# (U+2013 after cp1252 decoding); the plain-hyphen and U+FFFD spellings are
# accepted too so a mis-decoded file does not silently fall through to IMPACT.
# ---------------------------------------------------------------------------
_WEB = ("Brute Force", "XSS", "Sql Injection")
CIC2017_LABEL_TO_STAGE: dict[str, str] = {
    "FTP-Patator": INITIAL_ACCESS,          # credential brute force == 2018 FTP-BruteForce
    "SSH-Patator": INITIAL_ACCESS,          # == 2018 SSH-Bruteforce
    # Real labelled port-scan traffic: the only genuine RECONNAISSANCE ground truth among the CIC
    # datasets (2018 has none). Mapped directly, not via the port_scan_score heuristic.
    "PortScan": RECONNAISSANCE,
    # Heartbleed (CVE-2014-0160) is exploitation of a public-facing service to read memory:
    # T1190 Initial Access. It is also data theft, but the label says nothing about what was
    # read, so the conservative exploit-side stage is used (11 rows in the whole dataset).
    "Heartbleed": INITIAL_ACCESS,
    "DoS Hulk": IMPACT, "DoS GoldenEye": IMPACT, "DoS slowloris": IMPACT,
    "DoS Slowhttptest": IMPACT, "DDoS": IMPACT,
    **{f"Web Attack {dash} {kind}": INITIAL_ACCESS for dash in ("–", "-", "�") for kind in _WEB},
}
CIC_LABEL_TO_STAGE.update(CIC2017_LABEL_TO_STAGE)


# ---------------------------------------------------------------------------
# CTU-13 label mapping
# ---------------------------------------------------------------------------

def ctu13_label_to_stage(raw_label: str) -> str:
    """Map a CTU-13 flow label to an internal MITRE-style stage."""

    if raw_label is None:
        return IMPACT

    label = str(raw_label).strip().lower()

    # -----------------------------------------------------------------------
    # Normal / background traffic
    # -----------------------------------------------------------------------

    if label.startswith("flow=background"):
        return BENIGN

    if label.startswith("flow=to-background"):
        return BENIGN

    if label.startswith("flow=from-normal"):
        return BENIGN

    # D-1: these were missing and fell through to IMPACT (a positive).
    if label.startswith("flow=from-background"):
        return BENIGN

    if label.startswith("flow=to-normal"):
        return BENIGN

    # Bare "flow=normal" and versioned variants, e.g. flow=Normal-V45-HTTP-windowsupdate.
    if label.startswith("flow=normal"):
        return BENIGN

    # -----------------------------------------------------------------------
    # Botnet traffic
    # -----------------------------------------------------------------------

    if "from-botnet" in label:

        # Botnet communication/control activity.
        if any(
            keyword in label
            for keyword in [
                "irc",
                "dns",
                "http",
                "https",
                "cc",
                "custom-encryption",
                "encrypted",
                "attempt",
                "established",
            ]
        ):
            return COMMAND_AND_CONTROL

        # Malware/binary download activity.
        if "binary-download" in label:
            return INITIAL_ACCESS

        # Other botnet traffic is conservatively treated as C2.
        return COMMAND_AND_CONTROL

    # -----------------------------------------------------------------------
    # Unknown CTU-13 labels
    # -----------------------------------------------------------------------

    # Never silently classify unknown traffic as benign. It stays IMPACT, but
    # is no longer silent: warn once per distinct label (D-1 root cause was a
    # silent catch-all).
    if label not in _WARNED_CTU13_LABELS:
        _WARNED_CTU13_LABELS.add(label)
        _log.warning("Unknown CTU-13 label %r mapped to IMPACT (counts as a positive)", label)
    return IMPACT


# ---------------------------------------------------------------------------
# Unified label mapping
# ---------------------------------------------------------------------------

def label_to_stage(raw_label: str) -> str:
    """Map either CIC-IDS-2018 or CTU-13 labels to an internal stage."""

    if raw_label is None:
        return IMPACT

    label = str(raw_label).strip()

    # First try CIC-IDS-2018.
    if label in CIC_LABEL_TO_STAGE:
        return CIC_LABEL_TO_STAGE[label]

    # Handle CIC labels with different capitalization.
    normalized = label.lower()

    for cic_label, stage in CIC_LABEL_TO_STAGE.items():
        if normalized == cic_label.lower():
            return stage

    # CTU-13 labels start with "flow=".
    if normalized.startswith("flow="):
        return ctu13_label_to_stage(label)

    # NetFlow-v2 datasets (pipeline/adapters/netflow_v2_adapter.py) use "nf=<Attack>".
    if normalized.startswith("nf="):
        return nf_classify(label)[0]

    # UNSW-NB15 labels start with "unsw=" (see pipeline/adapters/unsw_nb15.py).
    if normalized.startswith("unsw="):
        return unsw_label_to_stage(label)

    # Unknown labels are excluded from the five-stage classification.
    return IMPACT


# ---------------------------------------------------------------------------
# UNSW-NB15 label mapping (D1: second permitted dataset, adds real
# Reconnaissance examples that CIC-IDS-2018 has none of)
# ---------------------------------------------------------------------------

UNSW_LABEL_TO_STAGE: dict[str, str] = {
    "normal": BENIGN,
    "reconnaissance": RECONNAISSANCE,
    # Foothold / code-execution categories -- closest kill-chain analogue is
    # gaining initial access to the host.
    "backdoor": INITIAL_ACCESS,
    "backdoors": INITIAL_ACCESS,
    "exploits": INITIAL_ACCESS,
    "shellcode": INITIAL_ACCESS,
    # Self-propagating across hosts is literally lateral movement.
    "worms": LATERAL_MOVEMENT,
    # Deliberately NOT mapped to a kill-chain stage -- conservative default of
    # IMPACT (excluded from the 5-way stage head), same treatment CIC-IDS-2018
    # DoS/DDoS gets. "Generic" is a block-cipher-complexity attack unrelated
    # to any single stage; "DoS" duplicates CIC's own impact category;
    # "Fuzzers" and "Analysis" are diagnostic/mixed categories (protocol
    # fuzzing, port scans, spam, html-file penetration) that don't cleanly
    # match one stage -- forcing them into Reconnaissance or Initial Access
    # would overstate what the label actually says.
}


def unsw_label_to_stage(raw_label: str) -> str:
    """Map a UNSW-NB15 ``unsw=<attack_cat or 'Normal'>`` label to an internal stage."""

    if raw_label is None:
        return IMPACT

    label = str(raw_label).strip().lower()
    if not label.startswith("unsw="):
        return IMPACT

    attack_cat = label[len("unsw="):].strip()
    return UNSW_LABEL_TO_STAGE.get(attack_cat, IMPACT)


# ---------------------------------------------------------------------------
# NetFlow-v2 (NF-UNSW-NB15-v2, NF-CSE-CIC-IDS2018-v2, NF-ToN-IoT-v2, NF-BoT-IoT-v2) attack names.
# Keyword rules on the lower-cased "Attack" string; the first matching rule wins. Anything no rule
# matches is IMPACT *and* reported as an unknown fall-through by the adapter toolkit.
# These datasets' exact label spellings were NOT available on disk when this was written, so the
# rules are deliberately keyword-based and conservative.
# ---------------------------------------------------------------------------
_NF_RULES: list[tuple[tuple[str, ...], str]] = [
    (("benign", "normal"), BENIGN),
    (("recon", "scan"), RECONNAISSANCE),
    (("infil", "worm"), LATERAL_MOVEMENT),
    (("bot", "c2", "c&c"), COMMAND_AND_CONTROL),
    (("theft", "exfil", "keylog"), EXFILTRATION),
    (("brute", "password", "backdoor", "exploit", "shellcode", "inject", "xss", "sql", "ftp", "ssh", "web"),
     INITIAL_ACCESS),
    # deliberately IMPACT (outside the five-stage head), same policy as CIC DoS/DDoS and UNSW Generic/Fuzzers
    (("ddos", "dos", "generic", "fuzz", "analysis", "ransom", "mitm"), IMPACT),
]


def nf_classify(raw_label: str) -> tuple[str, bool]:
    """(stage, matched_a_rule) for an ``nf=<Attack>`` label."""
    if raw_label is None:
        return IMPACT, False
    name = str(raw_label).strip().lower()
    if name.startswith("nf="):
        name = name[3:].strip()
    for keys, stage in _NF_RULES:
        if any(k in name for k in keys):
            return stage, True
    return IMPACT, False


# ---------------------------------------------------------------------------
# Stage -> model output index
# ---------------------------------------------------------------------------

def stage_to_index(
    stage: str,
    stage_labels: list[str] = STAGE_CLASSIFICATION_LABELS,
) -> int | None:
    """Return the model output index for a stage.

    Returns None for stages such as IMPACT that are excluded from the
    five-stage classification objective.
    """

    if stage not in stage_labels:
        return None

    return stage_labels.index(stage)