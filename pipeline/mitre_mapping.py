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

    # Never silently classify unknown traffic as benign.
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

    # Unknown labels are excluded from the five-stage classification.
    return IMPACT


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