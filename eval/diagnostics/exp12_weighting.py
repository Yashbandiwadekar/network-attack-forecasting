"""How much do the cross-dataset AUROCs rest on a few long series? Sequence-weighted vs unit-balanced AUROC for all 7 models
(CTU-13 unit = (scenario, src_ip); UNSW unit = src_ip), plus CTU without its dominant bot series."""
from eval.diagnostics.harness import *
from eval.diagnostics import core as c
import pandas as pd
rows = []
ctu = load(DS["ctu_contig"]); unsw = load(DS["unsw_contig"])
cu = np.char.add(np.char.add(ctu["scenario_id"].astype(str), "|"), ctu["src_ip"].astype(str))
yc = (ctu["infiltration"][:, 0] > 0).astype(float); yu = (unsw["infiltration"][:, 0] > 0).astype(float)
pos_units = pd.Series(cu[yc == 1]).value_counts()
print("CTU positive (scenario|ip) series:", len(pos_units), "sequences", int(yc.sum()), "largest 3:", pos_units.head(3).to_dict(),
      "-> share of positives in 3 largest: %.2f" % (pos_units.head(3).sum() / yc.sum()))
print("CTU negative series:", len(set(cu[yc == 0])), "| UNSW attacker hosts:", len(set(unsw['src_ip'][yu == 1].astype(str))),
      "benign hosts:", len(set(unsw['src_ip'][yu == 0].astype(str))))
top = pos_units.index[:3]
for name in MODELS:
    model, scaler = get_model(name)
    pc = score(model, scaler, ctu["X"]); pu = score(model, scaler, unsw["X"])
    keep = ~np.isin(cu, top)
    r = {"model": name,
         "ctu_seq": c._auc(yc, pc), "ctu_unit_balanced": c.unit_balanced_auroc(yc, pc, cu), "ctu_without_top3_pos_series": c._auc(yc[keep], pc[keep]),
         "unsw_seq": c._auc(yu, pu), "unsw_unit_balanced": c.unit_balanced_auroc(yu, pu, unsw["src_ip"].astype(str))}
    rows.append(r); print({k: (round(v, 3) if isinstance(v, float) else v) for k, v in r.items()}, flush=True)
pd.DataFrame(rows).to_csv(OUT / "weighting.csv", index=False)
