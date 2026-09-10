"""Deterministic MITRE-stage -> recommended first response action.

Not a general-purpose SOAR playbook engine — a small, honest mapping from the model's predicted
stage to the single most relevant first response action, so a forecast closes the loop from
"detect" to "respond" instead of stopping at a probability number. Every entry is deliberately
short: a real SOC analyst decides the specifics for their environment; this is a starting point
for triage, not automation, and nothing here is executed automatically.
"""
from __future__ import annotations

from pipeline.mitre_mapping import (
    BENIGN, COMMAND_AND_CONTROL, EXFILTRATION, IMPACT, INITIAL_ACCESS, LATERAL_MOVEMENT, RECONNAISSANCE,
)

RESPONSE_PLAYBOOK: dict[str, dict[str, str]] = {
    BENIGN: {
        "action": "No action needed",
        "detail": "Traffic matches learned benign dynamics.",
    },
    RECONNAISSANCE: {
        "action": "Increase monitoring on the targeted host/segment; rate-limit repeated connection attempts",
        "detail": "Scanning precedes exploitation — a cheap intervention now can prevent the next stage.",
    },
    INITIAL_ACCESS: {
        "action": "Force credential rotation on the targeted service; verify MFA is enabled; review auth logs",
        "detail": "A successful entry point has likely been established or is actively being attempted.",
    },
    LATERAL_MOVEMENT: {
        "action": "Isolate the host from internal network segments; audit SMB/RDP/WinRM session activity",
        "detail": "The attacker is likely pivoting toward higher-value internal targets.",
    },
    COMMAND_AND_CONTROL: {
        "action": "Block the destination IP/domain at the firewall/DNS; isolate the host; capture full "
                   "packet data for IOC extraction",
        "detail": "An active C2 channel gives the attacker ongoing remote control of the host.",
    },
    EXFILTRATION: {
        "action": "Block egress from the host immediately; snapshot for forensics; notify incident response",
        "detail": "Data may already be leaving the network — this is the highest-urgency stage.",
    },
    IMPACT: {
        "action": "Activate DDoS mitigation / upstream rate-limiting; fail over if available",
        "detail": "Traffic volume/pattern indicates a denial-of-service style impact rather than stealth.",
    },
}

_DEFAULT = {"action": "Manual review recommended", "detail": "No playbook entry for this stage."}


def recommended_action(stage: str) -> dict[str, str]:
    return RESPONSE_PLAYBOOK.get(stage, _DEFAULT)
