"""Maps CIC-IDS-2018 attack labels to MITRE ATT&CK stages.

CIC-IDS-2018 labels don't correspond 1:1 to the five stages the problem statement asks for
(Reconnaissance, Initial Access, Lateral Movement, Command & Control, Exfiltration). This module
makes the mapping explicit rather than silently forcing a bad fit — see docs/03-mitre-mapping.md
for the reasoning behind each row.

Two labels don't map onto any of the five stages at all:
  - DoS/DDoS labels are MITRE "Impact", not one of the five requested stages. They're kept in a
    separate `impact` bucket: still used for the binary infiltration-probability target, but
    excluded from the 5-way stage classification head.
  - `reconnaissance` has no direct CIC-IDS-2018 label. It is NOT assigned here; windowing.py
    derives it heuristically (benign windows with a high port-scan score that immediately precede
    an attack window from the same source IP).
"""
from __future__ import annotations

BENIGN = "benign"
RECONNAISSANCE = "reconnaissance"
INITIAL_ACCESS = "initial_access"
LATERAL_MOVEMENT = "lateral_movement"
COMMAND_AND_CONTROL = "command_and_control"
EXFILTRATION = "exfiltration"
IMPACT = "impact"  # not one of the PS's five stages; kept only for the binary target, see module docstring

# The five stages the classification head is trained on, plus benign. `impact` is deliberately
# excluded — windows labelled impact are dropped from the stage-classification loss (see
# models/world_model.py) but still contribute to the infiltration-probability loss.
STAGE_CLASSIFICATION_LABELS = [
    BENIGN,
    RECONNAISSANCE,
    INITIAL_ACCESS,
    LATERAL_MOVEMENT,
    COMMAND_AND_CONTROL,
    EXFILTRATION,
]

# Raw CIC-IDS-2018 `Label` column values -> stage. Covers the label spellings used across the
# 2018-02-14 .. 2018-03-02 CSVs (spelling/spacing is inconsistent in the original dataset).
CIC_LABEL_TO_STAGE: dict[str, str] = {
    "BENIGN": BENIGN,
    "Benign": BENIGN,
    "FTP-BruteForce": INITIAL_ACCESS,
    "SSH-Bruteforce": INITIAL_ACCESS,
    "Brute Force -Web": INITIAL_ACCESS,
    "Brute Force -XSS": INITIAL_ACCESS,
    "SQL Injection": INITIAL_ACCESS,
    "Infilteration": LATERAL_MOVEMENT,   # sic — this is the dataset's actual spelling
    "Infiltration": LATERAL_MOVEMENT,
    "Bot": COMMAND_AND_CONTROL,
    "DoS attacks-GoldenEye": IMPACT,
    "DoS attacks-Slowloris": IMPACT,
    "DoS attacks-SlowHTTPTest": IMPACT,
    "DoS attacks-Hulk": IMPACT,
    "DDOS attack-HOIC": IMPACT,
    "DDOS attack-LOIC-UDP": IMPACT,
    "DDoS attacks-LOIC-HTTP": IMPACT,
    # Synthetic-only label used by scripts/make_synthetic_sample.py to exercise the exfiltration
    # class end-to-end, since no CIC-IDS-2018 label maps to it. Not present in real data.
    "SYNTH-Exfiltration": EXFILTRATION,
}


def label_to_stage(raw_label: str) -> str:
    """Map a raw dataset label to a MITRE stage. Unknown labels fall back to `impact` rather than
    silently becoming benign, so pipeline bugs surface as visible unmapped-label warnings instead
    of corrupting the benign class."""
    return CIC_LABEL_TO_STAGE.get(raw_label.strip(), IMPACT)


def stage_to_index(stage: str, stage_labels: list[str] = STAGE_CLASSIFICATION_LABELS) -> int | None:
    """Index into the classification head's output for a stage, or None if it's excluded
    (i.e. `impact`) from the 5-way classification objective."""
    if stage not in stage_labels:
        return None
    return stage_labels.index(stage)
