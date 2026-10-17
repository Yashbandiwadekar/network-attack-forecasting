from eval.diagnostics.harness import *
from eval.diagnostics.harness import build_train_caches, OUT, CACHE, ROOT
build_train_caches()
from eval.diagnostics import core as c
import pandas as pd
pd.set_option("display.width", 300); pd.set_option("display.max_columns", 40); pd.set_option("display.max_rows", 100)
t = np.load(CACHE/"train_last.npz", allow_pickle=False)
sets = {}
for u in np.unique(t["day"]):
    m = t["day"]==u
    sets["tr"+str(u)[5:]] = (t["Xlast"][m], t["y"][m])
m = t["hasip"]==0
sets["tr_pseudo"] = (t["Xlast"][m], t["y"][m])
for k in ["cic18_val","cic18_test","ctu_contig","unsw_contig","cic17_60s"]:
    a = load(DS[k]); sets[k] = (a["X"][:,-1,:], (a["infiltration"][:,0]>0).astype(float))
    if k=="cic18_test":
        dd = day_of(a)
        for u in np.unique(dd): sets["te"+u[5:]] = (a["X"][dd==u][:,-1,:], (a["infiltration"][dd==u,0]>0).astype(float))
    if k=="cic18_val":
        dd = day_of(a)
        for u in np.unique(dd): sets["va"+u[5:]] = (a["X"][dd==u][:,-1,:], (a["infiltration"][dd==u,0]>0).astype(float))
rows = {}
for k,(X,y) in sets.items():
    rows[k] = c.univariate_auroc(X, y, NAMES)
df = pd.DataFrame(rows).round(2)
print(df.to_string())
df.to_csv(OUT/"univariate.csv")
# fraction zero / constant per set
print("\nconstant (std==0) features per set:")
for k,(X,y) in sets.items():
    const = [NAMES[j] for j in range(len(NAMES)) if np.ptp(X[:,j])==0]
    allzero = [NAMES[j] for j in range(len(NAMES)) if np.all(X[:,j]==0)]
    print(k, len(sets[k][1]), "pos", round(float(y.mean()),3), "n_const", len(const), "n_allzero", len(allzero), "| nonzero-const:", [n for n in const if n not in allzero])
    if k in ("ctu_contig","unsw_contig","cic17_60s","tr2018-02-20","te02-16","tr_pseudo"): print("   allzero:", allzero)
