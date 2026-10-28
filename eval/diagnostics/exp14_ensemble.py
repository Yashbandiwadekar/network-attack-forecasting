"""Inference-only: does averaging the scores of the 7 trained checkpoints (seed1 + 6 joint_v3, each with its own scaler)
change the per-day AUROCs? No fitting, no selection on test: the ensemble is all 7 models, fixed in advance."""
from eval.diagnostics.harness import *
from eval.diagnostics import core as c
from scipy.stats import rankdata
res = {}
for dk in ["cic18_val", "cic18_test"]:
    a = load(DS[dk]); y = (a["infiltration"][:, 0] > 0).astype(float); d = day_of(a)
    P = []
    for name in MODELS:
        model, scaler = get_model(name); P.append(score(model, scaler, a["X"]))
    P = np.array(P)
    for lab, s in [("mean_prob", P.mean(0)), ("mean_rank", np.mean([rankdata(p) for p in P], 0))]:
        u = c.per_unit_auroc(y, s, d)
        res[f"{dk}|{lab}"] = {"pooled": u["pooled"], "within": u["within"], "unit_mean": u["unit_mean"]}
        print(dk, lab, "pooled=%.3f day-constant=%.3f" % (u["pooled"], u["unit_mean"]), {k[5:]: round(v, 3) for k, v in u["within"].items()}, flush=True)
json.dump(res, open(OUT / "ensemble.json", "w"), indent=1, default=float)
