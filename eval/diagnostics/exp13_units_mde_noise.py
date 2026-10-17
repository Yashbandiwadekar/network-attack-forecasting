"""Independent units, minimum detectable effects, label-noise simulation (docs/16 sections on units and noise)."""
from eval.diagnostics.harness import *
from eval.diagnostics import core as c
import itertools, json
from scipy.stats import binom, t as tdist
out = {}
# 1. early-warning bounds
out["clopper_pearson"] = {f"{k}/{n}": c.clopper_pearson(k, n) for k, n in [(0, 12), (0, 15), (0, 27), (3, 15), (2, 15)]}
out["n_for_zero_events_to_exclude"] = {f"{p:.2f}": c.n_for_rate_zero_events(p) for p in (0.10, 0.20, 0.25, 0.30, 0.50)}
def n_to_separate(p0, p1, alpha=0.05, power=0.8):
    """smallest n for which the exact one-sided binomial test of H0: p<=p0 rejects with probability >= power when p=p1."""
    for n in range(3, 400):
        kcrit = int(binom.isf(alpha, n, p0)) + 1      # smallest k with P(X>=k | p0) <= alpha
        if binom.sf(kcrit - 1, n, p1) >= power:
            return n
out["episodes_needed_to_show_early_rate_above_10pct_if_true_30pct"] = n_to_separate(0.10, 0.30)
out["episodes_needed_to_show_early_rate_above_20pct_if_true_50pct"] = n_to_separate(0.20, 0.50)
# 2. AUROC MDE
out["hanley_mcneil_mde_vs_0.5"] = {f"{p}pos/{n}neg": round(c.min_detectable_auroc(0.5, p, n), 3)
                                   for p, n in [(12, 12), (12, 60), (10, 301), (4, 15), (50, 50), (200, 200)]}
# 3. paired per-day SD between the 7 models (test), MDE for a paired comparison over n days
A = json.load(open(OUT / "exp1_perday.json"))
names = list(MODELS)
days = ["2018-02-16", "2018-02-23", "2018-03-01"]
W = np.array([[A[f"{n}|best|cic18_test"]["within"][d] for d in days] for n in names])
diffs = np.array([W[i] - W[j] for i, j in itertools.combinations(range(len(names)), 2)])
sd_pair_day = float(diffs.std(ddof=1))
out["sd_of_paired_model_differences_per_day"] = round(sd_pair_day, 3)
out["per_day_sd_across_models"] = dict(zip(days, W.std(0, ddof=1).round(3).tolist()))
out["mde_paired_days"] = {}
for n in (3, 5, 10, 20):
    tcrit = tdist.ppf(0.975, n - 1) + tdist.ppf(0.8, n - 1)
    out["mde_paired_days"][str(n)] = round(float(tcrit * sd_pair_day / np.sqrt(n)), 3)
out["note_mde_paired_days"] = ("MDE of a paired per-day AUROC difference between two models, 80% power, two-sided 5%, using the observed SD of "
                               "seed-to-seed paired differences (all pairs of the 7 trained models) as the noise; it ignores training-seed variance "
                               "beyond these 7 models and day-to-day heterogeneity in the true difference, so it is a floor.")
# 4. label-noise simulation on the actual test/val windows, perfect ranker (ceiling the noise imposes)
te = load(DS["cic18_test"]); va = load(DS["cic18_val"])
sim = {}
for nm, a in [("test", te), ("val", va)]:
    y = (a["infiltration"][:, 0] > 0).astype(int)
    for fn, fp in [(0.0, 0.0), (0.07, 0.07), (0.10, 0.01), (0.25, 0.01), (0.0, 0.02), (0.0, 0.05)]:
        r = c.noisy_auroc(y, y.astype(float), fn, fp, reps=20)
        sim[f"{nm} fn={fn} fp={fp}"] = (round(r["mean"], 3), round(r["sd"], 3))
out["noise_perfect_ranker_ceiling"] = sim
# any-flow amplification: P(benign window flips to positive) when each benign flow is mislabeled with prob e
out["any_flow_amplification"] = {f"e={e}, {n} flows/window": round(1 - (1 - e) ** n, 3) for e in (1e-4, 5e-4, 1e-3) for n in (50, 250)}
json.dump(out, open(OUT / "units_mde_noise.json", "w"), indent=1, default=float)
print(json.dumps(out, indent=1, default=float))
