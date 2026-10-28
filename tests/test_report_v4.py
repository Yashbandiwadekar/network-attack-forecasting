import numpy as np

from eval import report_v4 as R


def test_day_table_within_day_and_mean():
    rng = np.random.default_rng(0)
    y = np.r_[(rng.random(300) < 0.5), (rng.random(300) < 0.1), np.zeros(10)].astype(int)
    day = np.array(["2018-02-16"] * 300 + ["2018-02-23"] * 300 + ["2018-03-01"] * 10)
    s = np.r_[y[:300] + 0.1 * rng.normal(size=300), rng.normal(size=300), rng.normal(size=10)]
    t = R.day_table(y, s, day)
    assert t["days"]["2018-02-16"]["auroc"] > 0.95 and abs(t["days"]["2018-02-23"]["auroc"] - 0.5) < 0.15
    assert t["days"]["2018-03-01"]["auroc"] is None and t["days"]["2018-03-01"]["auprc"] is None
    assert abs(t["mean_within_auroc"] - np.mean([t["days"]["2018-02-16"]["auroc"], t["days"]["2018-02-23"]["auroc"]])) < 1e-12


def test_unit_table_counts_weights_and_host_mean():
    rng = np.random.default_rng(1)
    # 3 positive hosts with 200 sequences each (high scores), 40 negative hosts with 2 sequences each (spread scores)
    unit = np.array([f"p{i}" for i, k in enumerate((50, 150, 400)) for _ in range(k)] + [f"n{i}" for i in range(40) for _ in range(2)])
    y = np.r_[np.ones(600), np.zeros(80)].astype(int)
    s = np.r_[np.r_[rng.normal(2.0, 1.0, 50), rng.normal(1.0, 1.0, 150), rng.normal(0.0, 1.0, 400)], rng.normal(0.0, 1.0, 80)]
    t = R.unit_table(y, s, unit, n_boot=50)
    assert (t["n_units"], t["n_pos_units"], t["n_neg_units"], t["n_sequences"]) == (43, 3, 40, 680)
    assert t["host_mean_ci95"][0] <= t["host_mean"] <= t["host_mean_ci95"][1] + 1e-9 or t["host_mean"] == 1.0
    assert t["unit_balanced"] is not None and t["seq_weighted"] is not None
    # unit weighting differs from sequence weighting when one unit dominates
    assert abs(t["unit_balanced"] - t["seq_weighted"]) > 1e-4
    one = R.unit_table(np.zeros(5), np.arange(5.0), np.array(list("aabbc")))
    assert one["seq_weighted"] is None and one["host_mean"] is None and one["host_mean_ci95"] is None


def _toy_result():
    names = R.MODEL_ORDER + R.BASELINE_ORDER
    sc = {n: {"auroc": 0.7, "auprc": 0.4} for n in names}
    day = {"n": 100, "pos": 10, "episodes": 2, "truncated": True, "scores": sc}
    def split(days):
        return {"days": {d: dict(day) for d in days}, "n_sequences": 100 * len(days), "n_pos": 10 * len(days), "n_episodes": 2 * len(days),
                "mean_within": {n: {"auroc": 0.7, "auprc": 0.4} for n in names}, "pooled": {n: 0.8 for n in names},
                "day_constant": {n: 0.6 for n in names}}
    ut = {"n_sequences": 10, "n_units": 5, "n_pos_units": 2, "n_neg_units": 3, "seq_weighted": 0.2, "unit_balanced": 0.5, "host_mean": 0.6,
          "host_mean_ci95": [0.4, 0.8]}
    blk = {"unit_definition": "ip", "episodes": "0", "scores": {n: dict(ut) for n in names},
           "counts": {k: ut[k] for k in ("n_sequences", "n_units", "n_pos_units", "n_neg_units")}}
    return {"generated": "2026-10-18", "anchors": {"seed1_test_pooled": 0.8003, "seed1_test_days": {"a": 0.9}, "hgb_last_test_pooled": 0.759,
            "lr_last_test_pooled": 0.666, "hgb_stacked_test_pooled": 0.764},
            "cic2018": {"test": split(["2018-02-16", "2018-02-23"]), "val": split(["2018-02-15"])},
            "cross_dataset": {"ctu13": blk, "unsw": blk, "cic2017": blk}}


def test_render_markdown_has_the_required_elements():
    md = R.render_markdown(_toy_result())
    assert "Truncated source days" in md and "1,048,575" in md
    assert "02-16 *" in md                                   # truncated days are starred
    assert "episodes" in md and "unit-balanced AUROC" in md and "5 units" in md
    assert "persistence_oracle" in md and "HGB_last" in md and "flow_count" in md and "LR_last" in md
    assert "secondary" in md.lower() and "Retired headlines" in md
