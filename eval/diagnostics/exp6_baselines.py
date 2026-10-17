from eval.diagnostics.harness import *
from eval.diagnostics.harness import build_train_caches, OUT, CACHE, ROOT
build_train_caches()
from eval.diagnostics import core as c
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
import pandas as pd, warnings
warnings.filterwarnings("ignore")
pd.set_option("display.width", 300); pd.set_option("display.max_columns", 40)
ix = {n:i for i,n in enumerate(NAMES)}
IDENT = ["has_ip_data","unique_dst_ips"]+["graph_out_degree","graph_fan_out_ratio","graph_fan_in_ratio","graph_component_size","graph_dst_entropy"]+[f"graph_embed_{i}" for i in range(8)]
ALLZERO_PKT = ["mean_ttl","var_ttl","mean_window_size","frag_ratio","mean_payload_size","std_payload_size","port_scan_score","retransmit_ratio","has_packet_features"]
def cols(drop): return [i for i,n in enumerate(NAMES) if n not in drop]
COUNT = ["flow_count","unique_dst_ports","total_bytes","total_packets","mean_duration","mean_iat","var_iat","max_iat"]
def logt(X):
    X = X.copy()
    for n in COUNT: X[:,ix[n]] = np.log1p(np.maximum(X[:,ix[n]],0))
    return X
# training sets
ts = np.load(CACHE/"train_sub.npz", allow_pickle=False)
trA = (ts["X"][:,-1,:], (ts["infiltration"][:,0]>0).astype(int), ts["window_end_time"].astype("datetime64[D]").astype(str))
b = load("data/processed_adapter/cic18c_v3:train")
trB = (b["X"][:,-1,:], (b["infiltration"][:,0]>0).astype(int))
evals = {}
for k in ["cic18_val","cic18_test","ctu_contig","unsw_contig","cic17_60s"]:
    a = load(DS[k]); evals[k] = (a["X"][:,-1,:], (a["infiltration"][:,0]>0).astype(int), day_of(a), a["current_infiltration"])
def fit_models(Xtr, ytr, tag):
    ms = {}
    for arm, drop in [("all", []), ("noident", IDENT)]:
        cs = cols(drop+ALLZERO_PKT)
        sc = StandardScaler().fit(Xtr[:,cs])
        lr = LogisticRegression(max_iter=1000).fit(sc.transform(Xtr[:,cs]), ytr)
        ms[f"LR_{arm}"] = (lambda X, lr=lr, sc=sc, cs=cs: lr.predict_proba(sc.transform(X[:,cs]))[:,1])
        Xl = logt(Xtr); sc2 = StandardScaler().fit(Xl[:,cs])
        lr2 = LogisticRegression(max_iter=1000).fit(sc2.transform(Xl[:,cs]), ytr)
        ms[f"LRlog_{arm}"] = (lambda X, lr=lr2, sc=sc2, cs=cs: lr.predict_proba(sc.transform(logt(X)[:,cs]))[:,1])
        hgb = HistGradientBoostingClassifier(max_iter=200, early_stopping=False, random_state=0).fit(Xtr[:,cs], ytr)
        ms[f"HGB_{arm}"] = (lambda X, h=hgb, cs=cs: h.predict_proba(X[:,cs])[:,1])
    return ms
rows = {}
for tag,(Xtr,ytr) in {"trainA(seed1-train,sub)":(trA[0],trA[1]),"trainB(contig)":trB}.items():
    ms = fit_models(Xtr, ytr, tag)
    for mn, f in ms.items():
        r = {}
        for k,(X,y,day,cur) in evals.items():
            p = f(X); u = c.per_unit_auroc(y,p,day)
            r[k] = u["pooled"]
            if k in ("cic18_test","cic18_val"):
                for d,v in u["within"].items(): r[f"{k}:{d[5:]}"] = v
                r[f"{k}:daymean"] = u["unit_mean"]
        rows[f"{mn} | {tag}"] = r
        print(mn, tag, {a: (None if v is None else round(v,3)) for a,v in r.items()}, flush=True)
# zero-training and oracle rows
for nm, fn in [("flow_count", lambda X,cur: X[:,ix["flow_count"]]), ("total_bytes", lambda X,cur: X[:,ix["total_bytes"]]), ("total_packets", lambda X,cur: X[:,ix["total_packets"]]),("persistence(oracle)", lambda X,cur: cur+1e-9*X[:,ix["flow_count"]])]:
    r = {}
    for k,(X,y,day,cur) in evals.items():
        u = c.per_unit_auroc(y, fn(X,cur), day); r[k]=u["pooled"]
        if k in ("cic18_test","cic18_val"):
            for d,v in u["within"].items(): r[f"{k}:{d[5:]}"] = v
            r[f"{k}:daymean"] = u["unit_mean"]
    rows[nm] = r
df = pd.DataFrame(rows).T.round(3)
df.to_csv(OUT/"baselines.csv"); print(df.to_string())
