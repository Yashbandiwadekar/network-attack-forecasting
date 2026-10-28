"""D-1 regression tests: benign CTU-13 labels must not map to a positive stage."""
import logging

import pytest

from pipeline import mitre_mapping
from pipeline.mitre_mapping import (
    BENIGN, COMMAND_AND_CONTROL, IMPACT, ctu13_label_to_stage, label_to_stage,
)


@pytest.mark.parametrize("label", [
    "flow=From-Background-CVUT-Proxy",
    "flow=To-Normal-V4x-UDP-NTP-server",
    "flow=To-Normal-V42-UDP-NTP-server",
    "flow=Normal-V4x-HTTP-windowsupdate",
    "flow=Normal-V45-HTTP-windowsupdate",
    "flow=Background",
    "flow=To-Background-UDP-CVUT-DNS-Server",
    "flow=From-Normal-V4-UDP-CVUT-DNS-Server",
    "flow=normal",
    "  FLOW=Normal  ",
])
def test_benign_ctu13_labels(label):
    assert ctu13_label_to_stage(label) == BENIGN
    assert label_to_stage(label) == BENIGN


@pytest.mark.parametrize("label", [
    "flow=From-Botnet-V51-1-TCP-Attempt",
    "flow=From-Botnet-V42-TCP-Established-HTTP-Ad-1",
    "flow=From-Botnet-V45-UDP-DNS",
    "flow=From-Botnet-V42-ICMP",
])
def test_botnet_labels_stay_non_benign(label):
    assert ctu13_label_to_stage(label) == COMMAND_AND_CONTROL


def test_unknown_ctu13_label_is_impact_and_warns_once(caplog):
    mitre_mapping._WARNED_CTU13_LABELS.discard("flow=totally-new-thing")
    with caplog.at_level(logging.WARNING, logger="pipeline.mitre_mapping"):
        assert ctu13_label_to_stage("flow=Totally-New-Thing") == IMPACT
        assert ctu13_label_to_stage("flow=Totally-New-Thing") == IMPACT
    msgs = [r for r in caplog.records if "totally-new-thing" in r.getMessage()]
    assert len(msgs) == 1


def test_known_labels_do_not_warn(caplog):
    with caplog.at_level(logging.WARNING, logger="pipeline.mitre_mapping"):
        ctu13_label_to_stage("flow=From-Background-CVUT-Proxy")
    assert not caplog.records
