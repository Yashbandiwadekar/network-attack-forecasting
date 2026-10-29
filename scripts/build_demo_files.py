"""Build the selectable demo scenarios (docs/22) from real public traffic.

    python -m scripts.search_demo_slices --out <dir>/search_0.jsonl        # 1. find each family's strongest slice
    python -m scripts.build_demo_files --out-dir <staging> --from-search <dir>/search_*.jsonl
                                                                          # 2. write the winning slices + manifest
    python -m scripts.build_demo_files --out-dir <staging> --measure --api http://127.0.0.1:<port>
                                                                          # 3. score each file via /demo/load
    python -m scripts.build_demo_files --out-dir <staging> --finalize     # 4. dashboard set -> demo/, rest documented
    python -m scripts.build_demo_files --out-dir <staging> --table        # markdown table of the result

Selection (owner's decision, 2026-10-29): the demos are the BEST-PERFORMING slices, so for each attack family
scripts/search_demo_slices.py tries a fixed grid of slices (3 lengths x 5 end points across the family's rows) and
keeps the one with the highest peak probability on a host whose 12 scored windows contain the attack. A family is
on the dashboard only if that peak reaches ALERT_THRESHOLD (0.40). The benign baseline (first rows after the last
attack of 02-23) is always on the dashboard as the false-alarm check. These are optimistic examples by
construction: the search is the selection. Every number shown is the measured output of the served bundle
(dist/models/seed1) on the exact file (step 3), the day tags come from the served config's split, and the full search
log and the families that never reached 0.40 are in docs/22 and the manifest's `documented_only` list (not served).

A catch = some host with peak >= 0.40 whose scored windows contain observed, non-heuristic attack stages; an alert on
all-Benign windows is not a catch.

The output is redistributed public data: demo/*.csv and demo/*.pcap are gitignored; only the scripts and
demo/demo_manifest.json are committed. Files are written with LF line endings so the sha256 in the manifest does
not depend on the OS. Deploy by COPYING the files (docs/22), not by regenerating on the server.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
from datetime import date
from pathlib import Path

import pandas as pd
import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RAW_CIC = PROJECT_ROOT / "data" / "raw" / "flows_real"
CTU13_PCAPS = Path("V:/Datasets/CTU-13-pcaps")
DEMO_DIR = PROJECT_ROOT / "demo"                 # --out-dir overrides (staging); --finalize writes to the real demo/
FINAL_DIR = PROJECT_ROOT / "demo"
SERVED_CONFIG = PROJECT_ROOT / "configs" / "real_data_v2_converged_seed1.yaml"

# ---- the slicing rule (fixed before any scoring; see module docstring) ----
N_ROWS = 40_000            # same as scripts/make_demo_capture.py
PRE_CONTEXT_ROWS = 2_000
SIZE_CAP_MB = 15.0
SHRINK_STEP = 5_000
GROW_STEP = 20_000
SEQUENCE_LENGTH = 12
ALERT_THRESHOLD = 0.40     # app/service.py ALERT_THRESHOLD: "flagged" means a host peaks at or above this

CIC_CITATION = (
    "CSE-CIC-IDS2018 (Canadian Institute for Cybersecurity / Communications Security Establishment), "
    "https://www.unb.ca/cic/datasets/ids-2018.html. Redistribution is allowed with citation: "
    "I. Sharafaldin, A. Habibi Lashkari, A. A. Ghorbani, 'Toward Generating a New Intrusion Detection "
    "Dataset and Intrusion Traffic Characterization', ICISSP 2018."
)
CTU13_CITATION = (
    "CTU-13, Stratosphere Laboratory, https://www.stratosphereips.org/datasets-ctu13 (no licence is "
    "stated on the dataset page). S. Garcia, M. Grill, J. Stiborek, A. Zunino, 'An empirical comparison "
    "of botnet detection methods', Computers & Security 45 (2014)."
)

# Every attack label in the CIC-2018 day files. `DAYS` maps the config's MM-DD to the raw file (whose name
# is DD-MM). Audited against the data at build time (audit_labels).
DAYS = {
    "02-14": "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv",
    "02-15": "Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv",
    "02-16": "Friday-16-02-2018_TrafficForML_CICFlowMeter.csv",
    "02-20": "Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv",
    "02-21": "Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv",
    "02-22": "Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv",
    "02-23": "Friday-23-02-2018_TrafficForML_CICFlowMeter.csv",
    "02-28": "Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv",
    "03-01": "Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv",
    "03-02": "Friday-02-03-2018_TrafficForML_CICFlowMeter.csv",
}
WEB_DESC = "Web brute force, XSS and SQL injection: a few hundred attack flows among benign traffic."
INFIL_DESC = "A foothold inside the network followed by internal activity."
LABELS = [  # (day, exact Label, short name, description)
    ("02-14", "FTP-BruteForce", "Brute force (FTP)", "Credential guessing against an FTP server."),
    ("02-14", "SSH-Bruteforce", "Brute force (SSH)", "Credential guessing against an SSH server."),
    ("02-15", "DoS attacks-GoldenEye", "DoS (GoldenEye)", "HTTP denial-of-service using GoldenEye."),
    ("02-15", "DoS attacks-Slowloris", "DoS (Slowloris)", "Slow-connection denial-of-service using Slowloris."),
    ("02-16", "DoS attacks-Hulk", "DoS (Hulk)", "HTTP flood denial-of-service using Hulk."),
    ("02-16", "DoS attacks-SlowHTTPTest", "DoS (SlowHTTPTest)", "Slow HTTP denial-of-service using SlowHTTPTest."),
    ("02-20", "DDoS attacks-LOIC-HTTP", "DDoS (LOIC-HTTP)",
     "Distributed HTTP flood from many attacker hosts. This day carries real source IPs, so several hosts are scored."),
    ("02-21", "DDOS attack-LOIC-UDP", "DDoS (LOIC-UDP)", "Distributed UDP flood using LOIC."),
    ("02-21", "DDOS attack-HOIC", "DDoS (HOIC)", "Distributed HTTP flood using HOIC."),
    ("02-22", "Brute Force -Web", "Web attacks", WEB_DESC),
    ("02-22", "Brute Force -XSS", "Web attacks", WEB_DESC),
    ("02-22", "SQL Injection", "Web attacks", WEB_DESC),
    ("02-23", "Brute Force -Web", "Web attacks", WEB_DESC),
    ("02-23", "Brute Force -XSS", "Web attacks", WEB_DESC),
    ("02-23", "SQL Injection", "Web attacks", WEB_DESC),
    ("02-28", "Infilteration", "Infiltration", INFIL_DESC),
    ("03-01", "Infilteration", "Infiltration", INFIL_DESC),
    ("03-02", "Bot", "Botnet / C2", "Bot command-and-control traffic."),
]
BENIGN = dict(id="benign", title="Benign baseline", scenario="benign", kind="cic", file=DAYS["02-23"],
              labels=(), rule="after_last_attack",
              description="Ordinary office traffic with no attack labels. A false-alarm check.")
PCAP = dict(id="ctu13_donbot", title="CTU-13 botnet capture (PCAP)", scenario="botnet-pcap", kind="pcap",
            file="6/botnet-capture-20110816-donbot.pcap", labels=(), rule="whole_file",
            description="A small raw PCAP of a Donbot capture from a different network and year. "
                        "Unlabelled, so no observed stages.")


# --------------------------------------------------------------------------- helpers

def _manifest() -> Path:
    return DEMO_DIR / "demo_manifest.json"


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def _split_days() -> dict[str, str]:
    """day (MM-DD) -> 'train' | 'val' | 'test', read from the served config, never hardcoded."""
    split = yaml.safe_load(SERVED_CONFIG.read_text(encoding="utf-8"))["split"]
    out = {}
    for role, key in (("train", "train_days"), ("val", "val_days"), ("test", "test_days")):
        for d in split.get(key, []):
            out[str(d)] = role
    return out


def _day_of(filename: str) -> tuple[str, date]:
    """'Friday-23-02-2018_...' (DD-MM-YYYY) -> ('02-23', date(2018, 2, 23)) in the config's MM-DD form."""
    m = re.search(r"(\d{2})-(\d{2})-(\d{4})", filename)
    if not m:
        raise ValueError(filename)
    dd, mm, yyyy = int(m.group(1)), int(m.group(2)), int(m.group(3))
    return f"{mm:02d}-{dd:02d}", date(yyyy, mm, dd)


def _labels(path: Path) -> pd.Series:
    return pd.concat(c["Label"] for c in pd.read_csv(path, usecols=["Label"], chunksize=1_000_000,
                                                      low_memory=False)).reset_index(drop=True)


def _first_target_row(path: Path, labels: tuple[str, ...]) -> int:
    n = 0
    for chunk in pd.read_csv(path, usecols=["Label"], chunksize=500_000, low_memory=False):
        hit = chunk["Label"].astype(str).isin(labels)
        if hit.any():
            return n + int(hit.to_numpy().argmax())
        n += len(chunk)
    raise SystemExit(f"{path.name}: no row labelled {labels}")


def audit_labels() -> None:
    """Stop if a day file carries an attack label that LABELS does not cover (the search must be complete)."""
    known = {(DAYS[d], lab) for d, lab, _, _ in LABELS}
    for f in DAYS.values():
        present = set(_labels(RAW_CIC / f).astype(str).unique()) - {"Benign", "Label"}
        missing = {(f, lab) for lab in present} - known
        if missing:
            raise SystemExit(f"attack labels not covered by LABELS: {sorted(missing)}")
        stale = {lab for ff, lab in known if ff == f} - present
        if stale:
            raise SystemExit(f"{f}: LABELS lists labels not in the file: {sorted(stale)}")


def plan_candidates() -> list[dict]:
    """One candidate per (day, label); labels of a day whose start rows coincide share one (identical file)."""
    groups: dict[tuple[str, int], dict] = {}
    for day, label, name, desc in LABELS:
        start = max(0, _first_target_row(RAW_CIC / DAYS[day], (label,)) - PRE_CONTEXT_ROWS)
        g = groups.setdefault((day, start), dict(day=day, start=start, labels=[], name=name, desc=desc))
        g["labels"].append(label)
    out = []
    for (day, start), g in groups.items():
        key = _slug(g["name"] if len(g["labels"]) > 1 else g["labels"][0])
        out.append(dict(id=f"{key}-{day.replace('-', '')}", title=f"{g['name']} ({day.replace('-', '/')})",
                        scenario=_slug(g["name"]), kind="cic", file=DAYS[day], labels=tuple(g["labels"]),
                        start=start, rule="from_first_label", description=g["desc"]))
    return out + [BENIGN, PCAP]


def _write_csv(src: Path, start: int, n: int, out: Path) -> pd.DataFrame:
    skip = range(1, start + 1) if start else None
    df = pd.read_csv(src, skiprows=skip, nrows=n, low_memory=False)
    out.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out, index=False, lineterminator="\n")
    return df


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _structure(path: Path, is_pcap: bool) -> dict:
    """Feature pipeline only (no model): the longest per-host window count and flows/windows totals."""
    sys.path.insert(0, str(PROJECT_ROOT))
    from app import service
    from common.config import load_config
    cfg = load_config(str(SERVED_CONFIG))
    flow_df, windows = service.process_uploads(None if is_pcap else path, path if is_pcap else None, cfg)
    per_host = windows.groupby("src_ip").size()
    return {"flows": int(len(flow_df)), "windows": int(len(windows)), "hosts": int(len(per_host)),
            "max_windows_per_host": int(per_host.max()) if len(per_host) else 0,
            "hosts_with_full_sequence": int((per_host >= SEQUENCE_LENGTH).sum())}


def verify_family_in_view(path: Path, labels: list[str]) -> dict | None:
    """The scored windows (each host's last 12) must really contain the family's flows, not just some other
    attack's: returns {host, labels: {label: flows}} for the host where the family's labels are the largest share of
    the flows in its scored windows (>= 50%), else None."""
    sys.path.insert(0, str(PROJECT_ROOT))
    from app import service
    from common.config import load_config
    flow_df, windows = service.process_uploads(path, None, load_config(str(SERVED_CONFIG)))
    best = None
    for host, g in windows.groupby("src_ip"):
        g = g.sort_values("window_start").iloc[-SEQUENCE_LENGTH:]
        if len(g) < SEQUENCE_LENGTH:
            continue
        t0, t1 = g["window_start"].min(), g["window_start"].max() + pd.Timedelta(seconds=10)
        f = flow_df[(flow_df["src_ip"] == host) & (flow_df["timestamp"] >= t0) & (flow_df["timestamp"] < t1)]
        mix = f["label"].astype(str).value_counts()
        share = float(mix[mix.index.isin(labels)].sum()) / max(1, int(mix.sum()))
        if share >= 0.5 and (best is None or share > best["share"]):
            best = dict(host=host, share=round(share, 3), labels={k: int(v) for k, v in mix.head(4).items()})
    return best


# --------------------------------------------------------------------------- build

def build_cic(sc: dict, split_days: dict[str, str]) -> dict | None:
    src = RAW_CIC / sc["file"]
    if not src.exists():
        print(f"[{sc['id']}] SKIP: {src} not found")
        return None
    day, d = _day_of(sc["file"])
    if sc["rule"] == "after_last_attack":
        lab = _labels(src)
        start = int(lab[(lab != "Benign") & (lab != "Label")].index.max()) + 1
    else:
        start = sc["start"]
    out = DEMO_DIR / f"demo-{sc['id']}.csv"
    n = sc.get("n") or N_ROWS
    grew = False
    while True:
        df = _write_csv(src, start, n, out)
        mb = out.stat().st_size / 1024 / 1024
        if mb > SIZE_CAP_MB:
            if grew:                          # growing for the 12-window requirement ran into the size cap
                print(f"[{sc['id']}] UNSUPPORTED: needs more than {SIZE_CAP_MB} MB to reach {SEQUENCE_LENGTH} windows")
                out.unlink(missing_ok=True)
                return None
            n -= SHRINK_STEP
            if n <= 0:
                print(f"[{sc['id']}] UNSUPPORTED: cannot fit under {SIZE_CAP_MB} MB")
                out.unlink(missing_ok=True)
                return None
            continue
        st = _structure(out, is_pcap=False)
        if st["hosts_with_full_sequence"] >= 1:
            break
        if len(df) < n:                       # ran out of file
            print(f"[{sc['id']}] UNSUPPORTED: no host reaches {SEQUENCE_LENGTH} windows ({st})")
            out.unlink(missing_ok=True)
            return None
        n, grew = n + GROW_STEP, True
    in_view = None
    if sc.get("rule") == "searched":
        in_view = verify_family_in_view(out, list(sc["labels"]))
        if in_view is None:
            print(f"[{sc['id']}] DROPPED: the scored windows do not contain this family's flows (another attack's windows)")
            out.unlink(missing_ok=True)
            return None
    lab = df["Label"].astype(str)
    mix = {k: int(v) for k, v in lab[lab != "Label"].value_counts().items()}   # 'Label' = repeated header rows in the raw file
    role = split_days.get(day, "unknown")
    return dict(
        id=sc["id"], title=sc["title"], description=sc["description"], scenario=sc["scenario"],
        target_labels=list(sc["labels"]),
        file=out.name, format="csv", size_bytes=out.stat().st_size, size_mb=round(out.stat().st_size / 1024 / 1024, 1),
        sha256=_sha256(out), n_rows=int(len(df)), label_mix=mix, structure=st, family_in_scored_windows=in_view,
        search=sc.get("search"),
        source=dict(dataset="CSE-CIC-IDS2018", day=d.strftime("%d %b %Y").lstrip("0"), day_mmdd=day,
                    file=sc["file"], row_start=int(start), row_end=int(start + len(df)),
                    rule=_rule_text(sc, start, len(df)), citation=CIC_CITATION),
        split=role, split_tag=_split_tag(role, day),
    )


def build_pcap(sc: dict) -> dict | None:
    src = CTU13_PCAPS / sc["file"]
    if not src.exists():
        print(f"[{sc['id']}] SKIP: {src} not found")
        return None
    out = DEMO_DIR / f"demo-{sc['id']}.pcap"
    DEMO_DIR.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, out)            # whole capture, byte-for-byte (scenario 6, the smallest, 5.3 MB)
    if out.stat().st_size / 1024 / 1024 > SIZE_CAP_MB:
        out.unlink()
        print(f"[{sc['id']}] UNSUPPORTED: over {SIZE_CAP_MB} MB")
        return None
    st = _structure(out, is_pcap=True)
    if st["hosts_with_full_sequence"] < 1:
        out.unlink()
        print(f"[{sc['id']}] UNSUPPORTED: no host reaches {SEQUENCE_LENGTH} windows ({st})")
        return None
    return dict(
        id=sc["id"], title=sc["title"], description=sc["description"], scenario=sc["scenario"], target_labels=[],
        file=out.name, format="pcap", size_bytes=out.stat().st_size, size_mb=round(out.stat().st_size / 1024 / 1024, 1),
        sha256=_sha256(out), n_rows=None, label_mix={}, structure=st,
        source=dict(dataset="CTU-13 (scenario 6, Donbot)", day="16 Aug 2011", day_mmdd=None,
                    file=Path(sc["file"]).name, row_start=None, row_end=None,
                    rule="whole capture, copied byte-for-byte (IPv4 TCP/UDP only is parsed)",
                    citation=CTU13_CITATION),
        split="cross_dataset", split_tag="CROSS-DATASET (never seen in training)",
    )


def _rule_text(sc: dict, start: int, n: int) -> str:
    if sc["rule"] == "after_last_attack":
        return f"rows {start}..{start + n - 1}: the first {n} rows after the last non-benign row of the day"
    if sc["rule"] == "searched":
        return (f"rows {start}..{start + n - 1}: the slice with the strongest alert for this family in the search grid "
                f"(scripts/search_demo_slices.py)")
    return (f"rows {start}..{start + n - 1}: {PRE_CONTEXT_ROWS} rows before the first {' / '.join(sc['labels'])} "
            f"row of the day (or row 0), then {n} consecutive rows")


def _split_tag(role: str, day: str) -> str:
    return {"train": "TRAIN DAY (in-sample)", "val": "VALIDATION DAY", "test": "HELD-OUT TEST DAY"}.get(
        role, f"DAY {day} NOT IN SPLIT")


def plan_from_search(logs: list[Path]) -> tuple[list[dict], dict]:
    """Winner per family from the search logs (highest catch peak, ties -> earliest), if it reaches ALERT_THRESHOLD;
    plus the benign baseline. Returns (candidates, search summary)."""
    sys.path.insert(0, str(PROJECT_ROOT))
    from scripts.search_demo_slices import families
    recs = [json.loads(line) for p in logs for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]
    cands, summary = [], {}
    for fam in families():
        mine = [r for r in recs if r["family"] == fam["id"]]
        scored = [r for r in mine if "peak_max" in r]
        winners = sorted((r for r in scored if r.get("catch")), key=lambda r: (-r["catch"]["peak"], r["n"], r["start"]))
        best = winners[0] if winners else None
        summary[fam["id"]] = dict(day=fam["day"], labels=fam["labels"], slices_tried=len(mine), slices_scored=len(scored),
                                  best_search_peak=best["catch"]["peak"] if best else None,
                                  best_slice=[best["start"], best["start"] + best["n"]] if best else None)
        name = fam["name"]
        desc = next(d for dy, lb, nm, d in LABELS if dy == fam["day"] and lb == fam["labels"][0])
        if best and best["catch"]["peak"] >= ALERT_THRESHOLD:
            cands.append(dict(id=fam["id"], title=name, scenario=_slug(name), kind="cic",
                              file=fam["file"], labels=tuple(fam["labels"]), start=best["start"], n=best["n"],
                              rule="searched", description=desc, search=summary[fam["id"]]))
    return cands + [BENIGN], summary


def build_all(only: list[str] | None, search_logs: list[Path] | None = None) -> None:
    DEMO_DIR.mkdir(parents=True, exist_ok=True)
    split_days = _split_days()
    summary = {}
    if search_logs:
        cands, summary = plan_from_search(search_logs)
    else:
        print("auditing attack labels in the day files ...")
        audit_labels()
        cands = plan_candidates()
    print(f"{len(cands)} candidates: " + ", ".join(c["id"] for c in cands))
    entries = []
    for sc in cands:
        if only and sc["id"] not in only:
            continue
        print(f"[{sc['id']}] building ...")
        e = build_cic(sc, split_days) if sc["kind"] == "cic" else build_pcap(sc)
        if e is None:
            continue
        print(f"[{sc['id']}] {e['file']}  {e['size_mb']} MB  {e['structure']}  {e['label_mix']}")
        entries.append(e)
    _write_manifest(entries, [], {"search": summary} if summary else None)


def _write_manifest(entries: list[dict], documented: list[dict], extra: dict | None = None, where: Path | None = None) -> None:
    doc = {
        "generated_by": "scripts/build_demo_files.py",
        "pandas_version": pd.__version__,
        "slicing_rule": dict(n_rows=N_ROWS, pre_context_rows=PRE_CONTEXT_ROWS, size_cap_mb=SIZE_CAP_MB,
                             shrink_step=SHRINK_STEP, grow_step=GROW_STEP, sequence_length=SEQUENCE_LENGTH),
        "served_model": "dist/models/seed1 (configs/real_data_v2_converged_seed1.yaml)",
        "alert_threshold": ALERT_THRESHOLD,
        **(extra or {}),
        "scenarios": entries,                 # the dashboard list: what GET /api/v1/demo/scenarios serves
        "documented_only": documented,        # measured, not shown on the dashboard (docs/22)
    }
    path = where or _manifest()
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {path} ({len(entries)} dashboard, {len(documented)} documented-only)")


# --------------------------------------------------------------------------- measure

def derive_expected_behaviour(entry: dict, m: dict) -> dict:
    """Verdict + text from the measured numbers and the day's split role. Mechanical on purpose."""
    attack = entry["scenario"] != "benign"
    if not m.get("hosts_scored"):
        return {"verdict": "not_scored",
                "text": "The served model could not score this file: no host has 12 consecutive windows."}
    flagged = m["peak_prob"] >= ALERT_THRESHOLD
    runs = m.get("top_host_observed_runs") or []
    labelled = bool(runs) and all(r.get("observed") for r in runs)
    catch = m.get("catch")                      # best flagged host whose scored windows contain the attack
    if not attack:
        verdict = "false_alarm" if flagged else "correct_quiet"
    elif catch:
        verdict = "flagged"
    elif flagged and not labelled:
        verdict = "flagged_unverifiable"        # unlabelled capture: an alert cannot be tied to an attack
    elif flagged:
        verdict = "alert_on_benign_windows"
    elif labelled and all(r["stage"] == "Benign" for r in runs):
        verdict = "out_of_view"
    else:
        verdict = "missed"
    shown_peak = catch["peak_prob"] if catch else m["peak_prob"]
    show_runs = catch["observed_runs"] if catch else runs
    stages = ", ".join(f"{r['stage']} x{r['n_windows']}" for r in show_runs) if show_runs and show_runs[0].get("observed") else ""
    n_alert = m["high_risk_hosts"]
    if verdict == "flagged":
        text = (f"Alerts: peak {shown_peak:.2f} on the alerting host"
                + (f", {n_alert} of {m['hosts_scored']} hosts flagged" if m["hosts_scored"] > 1 else "")
                + (f". Scored windows: {stages}." if stages else "."))
    elif verdict == "correct_quiet":
        text = f"Stays quiet: peak {m['peak_prob']:.2f}, below the {ALERT_THRESHOLD:.2f} alert threshold. A false-alarm check."
    else:
        text = f"Peak {m['peak_prob']:.2f} across {m['hosts_scored']} scored host(s), {n_alert} at or above {ALERT_THRESHOLD:.2f} ({verdict})."
    role = entry.get("split")
    tag = {"train": "Training day (in-sample).", "val": "Validation day.", "test": "Held-out test day.",
           "cross_dataset": "Different network and year (cross-dataset)."}.get(role)
    if tag:
        text += " " + tag
    return {"verdict": verdict, "text": text}


def _runs(pred: dict) -> list[dict]:
    return [{k: run[k] for k in ("stage", "observed", "n_windows", "flow_count", "from", "to", "may_be_heuristic")}
            for run in pred["observed_history"]["runs"]]


def _attack_in_view(runs: list[dict]) -> bool:
    """Observed, non-heuristic, non-Benign stage among the scored windows."""
    return any(r["observed"] and r["stage"] != "Benign" and not r.get("may_be_heuristic") for r in runs)


def measure(api: str, only: list[str] | None) -> None:
    import requests
    doc = json.loads(_manifest().read_text(encoding="utf-8"))
    health = requests.get(f"{api}/api/v1/health", timeout=60).json()
    for e in doc["scenarios"]:
        if only and e["id"] not in only:
            continue
        print(f"[{e['id']}] loading on {api} ...")
        r = requests.post(f"{api}/api/v1/demo/load", json={"id": e["id"]}, timeout=3600)
        if r.status_code != 200:
            raise SystemExit(f"[{e['id']}] load failed: {r.status_code} {r.text}")
        res = r.json()
        hosts = requests.get(f"{api}/api/v1/forecast/hosts", timeout=300).json().get("hosts", [])
        flagged_hosts = [h for h in hosts if h["peak_prob"] >= ALERT_THRESHOLD]
        m = {"status": res["status"], "flows": res["extracted_flows"], "windows": res["windows"],
             "hosts_scored": res["hosts_scored"], "high_risk_hosts": len(res.get("high_risk_hosts") or []),
             "peak_prob": None, "top_host": None, "top_host_severity": None, "top_host_predicted_stage": None,
             "top_host_observed_runs": None, "catch": None, "alert_threshold": ALERT_THRESHOLD}
        if hosts:
            top = hosts[0]                                 # sorted by peak_prob, descending
            m.update(peak_prob=top["peak_prob"], top_host=top["host_ip"], top_host_severity=top["severity"],
                     top_host_predicted_stage=top["predicted_stage"])
            best = None
            for h in ([top] + [x for x in flagged_hosts if x["host_ip"] != top["host_ip"]]):
                pred = requests.post(f"{api}/api/v1/forecast/predict", json={"host_ip": h["host_ip"]}, timeout=300).json()
                runs = _runs(pred)
                if h is top:
                    m["top_host_observed_runs"] = runs
                if h["peak_prob"] >= ALERT_THRESHOLD and _attack_in_view(runs) and best is None:
                    best = {"host": h["host_ip"], "peak_prob": h["peak_prob"], "observed_runs": runs}   # hosts are peak-sorted
            m["catch"] = best
        e["measured"] = m
        e["expected_behaviour"] = derive_expected_behaviour(e, m)
        print(f"[{e['id']}] peak={m['peak_prob']} hosts={m['hosts_scored']} high_risk={m['high_risk_hosts']} "
              f"-> {e['expected_behaviour']['verdict']}")
    b = health.get("bundle") or {}
    doc["measured_with"] = {"model": "bundle dist/models/seed1", "bundle_name": b.get("name"),
                            "bundle_manifest_sha256": b.get("manifest_sha256"),
                            "bundle_checksums_ok": b.get("checksums_ok"), "status": health.get("status")}
    _manifest().write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print(f"updated {_manifest()}")


def finalize() -> None:
    """Dashboard set = benign baseline (correct_quiet) + every CATCH; the rest becomes documented_only.
    Copies the dashboard files to the real demo/ dir, writes its manifest and removes demo files that are no
    longer used (never the old walkthrough capture)."""
    doc = json.loads(_manifest().read_text(encoding="utf-8"))
    keep, doc_only = [], []
    for e in doc["scenarios"] + doc.get("documented_only", []):
        if e.get("expected_behaviour", {}).get("verdict") in ("flagged", "correct_quiet"):
            keep.append(e)
        else:
            doc_only.append(e)
    FINAL_DIR.mkdir(parents=True, exist_ok=True)
    for e in keep:
        dst = FINAL_DIR / e["file"]
        if DEMO_DIR.resolve() != FINAL_DIR.resolve():
            shutil.copyfile(DEMO_DIR / e["file"], dst)
        assert _sha256(dst) == e["sha256"], e["id"]
    wanted = {e["file"] for e in keep}
    for f in list(FINAL_DIR.glob("demo-*.csv")) + list(FINAL_DIR.glob("demo-*.pcap")):
        if f.name not in wanted and not f.name.startswith("demo-capture-"):
            f.unlink()
            print(f"removed unused {f.name}")
    for e in doc_only:                                   # documented-only entries keep their numbers, not a file
        e["file_removed"] = True
    extra = {k: doc[k] for k in ("measured_with",) if k in doc}
    _write_manifest(keep, doc_only, extra, FINAL_DIR / "demo_manifest.json")
    print("dashboard total size: %.1f MB" % (sum(e["size_bytes"] for e in keep) / 1024 / 1024))


def document_search(logs: list[Path]) -> None:
    """Write the full per-family search outcome into the manifest: `search` (every family) and `documented_only`
    (families that did not make the dashboard, with their best measured search numbers; the API never serves them)."""
    sys.path.insert(0, str(PROJECT_ROOT))
    from scripts.search_demo_slices import families
    path = FINAL_DIR / "demo_manifest.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    recs = [json.loads(line) for p in logs for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]
    on_dash = {e["id"] for e in doc["scenarios"]}
    summary, documented = {}, []
    for fam in families():
        mine = [r for r in recs if r["family"] == fam["id"]]
        scored = [r for r in mine if "peak_max" in r]
        catchable = [r for r in scored if r.get("catch")]
        best = max(catchable, key=lambda r: r["catch"]["peak"]) if catchable else None
        anyb = max(scored, key=lambda r: r["peak_max"]) if scored else None
        skips = {}
        for r in mine:
            if "skipped" in r:
                key = re.sub(r"[0-9.]+", "N", r["skipped"])
                skips[key] = skips.get(key, 0) + 1
        row = dict(id=fam["id"], day=fam["day"], labels=fam["labels"], slices_tried=len(mine), slices_scored=len(scored),
                   slices_skipped=skips, best_attack_in_view_peak=best["catch"]["peak"] if best else None,
                   best_attack_in_view_slice=[best["start"], best["start"] + best["n"]] if best else None,
                   highest_peak_any_window=anyb["peak_max"] if anyb else None, on_dashboard=fam["id"] in on_dash)
        summary[fam["id"]] = row
        if fam["id"] not in on_dash:
            documented.append(dict(row, reason="no scored slice reached the 0.40 alert threshold with the attack in view"
                                   if not (best and best["catch"]["peak"] >= ALERT_THRESHOLD)
                                   else "excluded: the scored windows do not contain this family's own flows"))
    doc["search"] = summary
    doc["documented_only"] = documented
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print(f"documented {len(documented)} families not on the dashboard")


def table() -> None:
    doc = json.loads(_manifest().read_text(encoding="utf-8"))
    print("| candidate | label(s) | day | tag | rows | peak | scored windows (top host) | verdict |")
    print("|---|---|---|---|---|---|---|---|")
    for e in doc["scenarios"] + doc.get("documented_only", []):
        m = e.get("measured") or {}
        runs = (m.get("catch") or {}).get("observed_runs") or m.get("top_host_observed_runs") or []
        stages = ", ".join(f"{r['stage']} x{r['n_windows']}" for r in runs) or "-"
        peak = (m.get("catch") or {}).get("peak_prob", m.get("peak_prob"))
        print(f"| {e['id']} | {' / '.join(e.get('target_labels') or []) or '-'} | {e['source']['day']} | "
              f"{e['split_tag']} | {e['n_rows'] or 'whole file'} | {peak} (max {m.get('peak_prob')}, "
              f"{m.get('high_risk_hosts')}/{m.get('hosts_scored')} hosts) | {stages} | "
              f"{e.get('expected_behaviour', {}).get('verdict')} |")


def main() -> None:
    global DEMO_DIR
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out-dir", type=Path, default=DEMO_DIR, help="staging dir for the candidates and their manifest")
    ap.add_argument("--measure", action="store_true", help="score every file via a running server and record it")
    ap.add_argument("--api", default="http://127.0.0.1:8766")
    ap.add_argument("--from-search", nargs="+", type=Path, help="search logs; build each family's winning slice")
    ap.add_argument("--document-search", nargs="+", type=Path, help="write the per-family search outcome into demo/ manifest")
    ap.add_argument("--only", nargs="*", help="restrict to these scenario ids")
    ap.add_argument("--rederive", action="store_true",
                    help="recompute expected_behaviour from the stored measurements (no server needed)")
    ap.add_argument("--finalize", action="store_true", help="dashboard set (benign + catches) -> demo/, rest documented_only")
    ap.add_argument("--table", action="store_true", help="print the markdown table of every candidate")
    args = ap.parse_args()
    DEMO_DIR = args.out_dir.resolve()
    if args.rederive:
        doc = json.loads(_manifest().read_text(encoding="utf-8"))
        for e in doc["scenarios"] + doc.get("documented_only", []):
            if e.get("measured"):
                e["expected_behaviour"] = derive_expected_behaviour(e, e["measured"])
        _manifest().write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    elif args.measure:
        measure(args.api, args.only)
    elif args.document_search:
        document_search(args.document_search)
    elif args.finalize:
        finalize()
    elif args.table:
        table()
    else:
        build_all(args.only, args.from_search)


if __name__ == "__main__":
    main()
