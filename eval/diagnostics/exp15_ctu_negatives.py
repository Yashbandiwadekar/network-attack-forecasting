"""Which negatives drive the CTU-13 inversion? Sequence-level and host-mean AUROC with the negative class restricted to
(a) internal hosts (147.32.84.x, the campus subnet the bots live in), (b) hosts with at least as many sequences as the
smallest positive series. Post-hoc diagnostic, fixed subsets, no tuning."""
from eval.diagnostics.harness import *
from eval.diagnostics import core as c
import pandas as pd
a = load(DS["ctu_contig"]); y = (a["infiltration"][:, 0] > 0).astype(float); ips = a["src_ip"].astype(str)
scen = a["scenario_id"].astype(str); unit = np.char.add(np.char.add(scen, "|"), ips)
internal = np.array([s.startswith("147.32.84.") for s in ips])
sizes = pd.Series(unit).value_counts(); min_pos = sizes[pd.Series(unit[y == 1]).unique()].min()
big = np.isin(unit, sizes.index[sizes >= min_pos])
print("min positive series size", int(min_pos), "| negative series total", len(set(unit[y == 0])), "internal", len(set(unit[(y == 0) & internal])),
      "with >= min_pos seq", len(set(unit[(y == 0) & big])))
rows = []
for name in MODELS:
    model, scaler = get_model(name); p = score(model, scaler, a["X"])
    r = {"model": name}
    for lab, keep in [("all", np.ones(len(y), bool)), ("neg_internal_only", (y == 1) | internal), ("neg_big_series_only", (y == 1) | big)]:
        yy, pp, uu, ii = y[keep], p[keep], unit[keep], ips[keep]
        df = pd.DataFrame({"u": uu, "y": yy, "p": pp}).groupby("u").agg(y=("y", "max"), p=("p", "mean"))
        r[lab + "_seq"] = c._auc(yy, pp); r[lab + "_unitbal"] = c.unit_balanced_auroc(yy, pp, uu); r[lab + "_unitmean"] = c._auc(df["y"].values, df["p"].values)
    rows.append(r)
    print({k: (round(v, 3) if isinstance(v, float) else v) for k, v in r.items()}, flush=True)
pd.DataFrame(rows).to_csv(OUT / "ctu_negatives.csv", index=False)
