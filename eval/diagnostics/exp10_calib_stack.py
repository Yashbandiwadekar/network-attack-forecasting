from eval.diagnostics.harness import *
from eval.diagnostics.harness import build_train_caches, OUT, CACHE, ROOT
build_train_caches()
from eval.diagnostics import core as c
from sklearn.ensemble import HistGradientBoostingClassifier
import json, warnings; warnings.filterwarnings("ignore")
ix = {n:i for i,n in enumerate(NAMES)}
A = json.load(open(OUT/"exp1_perday.json"))
for dk in ["cic18_val","cic18_test"]:
    for m in ["seed1|best","B_s3|best","Bplus_s1|best"]:
        r = A[f"{m}|{dk}"]
        print(dk, m, {d[5:]:(round(r['unit_mean_score'][d],3), round(r['unit_rate'][d],3)) for d in r['unit_rate']}, "(mean score, observed rate)")
# paired per-day difference sd among 7 best models on test
names = ["seed1","B_s1","B_s2","B_s3","Bplus_s1","Bplus_s2","Bplus_s3"]
days = ["2018-02-16","2018-02-23","2018-03-01"]
W = np.array([[A[f"{n}|best|cic18_test"]["within"][d] for d in days] for n in names])
import itertools
diffs = np.array([W[i]-W[j] for i,j in itertools.combinations(range(7),2)])
print("per-day AUROC by model (test):"); print(np.round(W,3))
print("SD across models of per-day AUROC:", np.round(W.std(0,ddof=1),3), " SD of paired model differences per day:", np.round(diffs.std(0,ddof=1),3), "overall pooled paired-diff SD", round(diffs.std(),3))
Wv = np.array([[A[f"{n}|best|cic18_val"]["within"][d] for d in ["2018-02-15","2018-02-22"]] for n in names]); print("val per-day AUROC by model:\n", np.round(Wv,3))
# stacked-history HGB
def stack(X):
    last = X[:,-1,:]; mean = X.mean(1); std = X.std(1); d1 = X[:,-1,:]-X[:,-2,:]; d6 = X[:,-1,:]-X[:,-7,:]; mx = X.max(1)
    return np.concatenate([last,mean,std,d1,d6,mx],1)
ts = np.load(CACHE/"train_sub.npz", allow_pickle=False)
b = load("data/processed_adapter/cic18c_v3:train")
trs = {"trainA":(stack(ts["X"]), (ts["infiltration"][:,0]>0).astype(int)), "trainB":(stack(b["X"]), (b["infiltration"][:,0]>0).astype(int))}
ev = {k: load(DS[k]) for k in ["cic18_val","cic18_test","ctu_contig","unsw_contig","cic17_60s"]}
for tn,(Xtr,ytr) in trs.items():
    h = HistGradientBoostingClassifier(max_iter=200, early_stopping=False, random_state=0).fit(Xtr,ytr)
    for k,a in ev.items():
        p = h.predict_proba(stack(a["X"]))[:,1]; y=(a["infiltration"][:,0]>0).astype(float)
        u = c.per_unit_auroc(y,p,day_of(a))
        print("HGB_stack",tn,k,"pooled",round(u["pooled"],3),"within",{d[5:]:round(v,3) for d,v in u["within"].items()} if k.startswith("cic18") else "", flush=True)
