"""One-off: derive configs/cic_pkt.yaml and configs/cic_pkt_flowonly.yaml from the UNSW pilot config (same features,
model and hyper-parameters -- only paths and the split section change)."""
from pathlib import Path

root = Path(__file__).resolve().parent.parent
c = (root / "configs" / "unsw_nb15_pkt.yaml").read_text(encoding="utf-8")

i, j = c.index("paths:"), c.index("windowing:")
c = c[:i] + (
    "paths:\n"
    '  raw_flow_dir: "V:/Datasets/CIC-IDS-2018/Wednesday-14-02-2018/pcap"\n'
    '  raw_pcap_dir: "V:/Datasets/CIC-IDS-2018/Wednesday-14-02-2018/pcap"\n'
    "  processed_dir: data/processed_cic_pkt\n"
    "  checkpoint_dir: checkpoints_cic_pkt\n"
    "  eval_report: docs/04-evaluation-cic-pkt.md\n\n"
) + c[j:]

i, j = c.index("split:"), c.index("model:")
c = c[:i] + (
    "split:\n"
    "  # Time split of the single day (see pipeline/build_cic_pkt_dataset.py): train = FTP-Patator period, test = the\n"
    "  # later, unseen SSH-Patator period, val carved from inside the FTP period.\n"
    "  mode: by_time\n"
    "  val_positive_quantile: 0.75\n\n"
) + c[j:]
c = "# CIC-IDS-2018 Wed 14-02-2018 PACKET-AWARE (built from raw PCAP). Writes only to *_cic_pkt paths.\n" + c
(root / "configs" / "cic_pkt.yaml").write_text(c, encoding="utf-8")

flow = (
    c.replace("data/processed_cic_pkt\n", "data/processed_cic_pkt_flowonly\n")
    .replace("checkpoints_cic_pkt\n", "checkpoints_cic_pkt_flowonly\n")
    .replace("04-evaluation-cic-pkt.md", "04-evaluation-cic-pkt-flowonly.md")
)
flow = "# CONTROL for configs/cic_pkt.yaml: identical data and hyper-parameters, packet-level columns zeroed.\n" + flow
(root / "configs" / "cic_pkt_flowonly.yaml").write_text(flow, encoding="utf-8")
print("wrote configs/cic_pkt.yaml and configs/cic_pkt_flowonly.yaml")
