from eval.diagnostics.harness import *
from eval.diagnostics.harness import build_train_caches, OUT, CACHE, ROOT
build_train_caches()
from eval.diagnostics import core as c
from sklearn.ensemble import HistGradientBoostingClassifier
import pandas as pd, warnings
warnings.filterwarnings("ignore")
ix = {n:i for i,n in enumerate(NAMES)}
IDENT = ["has_ip_data","unique_dst_ips"]+["graph_out_degree","graph_fan_out_ratio","graph_fan_in_ratio","graph_component_size","graph_dst_entropy"]+[f"graph_embed_{i}" for i in range(8)]
ALLZ = ["mean_ttl","var_ttl","mean_window_size","frag_ratio","mean_payload_size","std_payload_size","port_scan_score","retransmit_ratio","has_packet_features"]
ts = np.load(CACHE/"train_sub.npz", allow_pickle=False)
tl = np.load(CACHE/"train_last.npz", allow_pickle=False)
X, Y, D, CUR = [ts["X"][:,-1,:]], [(ts["infiltration"][:,0]>0).astype(int)], [ts["window_end_time"].astype("datetime64[D]").astype(str)], [ts["current_infiltration"]]
for k in ["cic18_val","cic18_test"]:
    a = load(DS[k]); X.append(a["X"][:,-1,:]); Y.append((a["infiltration"][:,0]>0).astype(int)); D.append(day_of(a)); CUR.append(a["current_infiltration"])
X=np.concatenate(X); Y=np.concatenate(Y); D=np.concatenate(D); CUR=np.concatenate(CUR)
days = sorted(np.unique(D))
print(days, {d:int((D==d).sum()) for d in days})
rows = {}
for held in days:
    tr = D!=held
    if held=="2018-02-20":
        m = tl["day"]=="2018-02-20"; Xte, yte = tl["Xlast"][m], tl["y"][m].astype(int)
        rng=np.random.default_rng(0); sel=rng.choice(len(yte), 200000, replace=False); Xte,yte=Xte[sel],yte[sel]
        cur=None
    else:
        Xte, yte = X[~tr], Y[~tr]; cur = CUR[~tr]
    r = {"n":len(yte),"pos":round(float(yte.mean()),3)}
    for arm, drop in [("all",[]),("noident",IDENT)]:
        cs = [i for i,n in enumerate(NAMES) if n not in drop+ALLZ]
        h = HistGradientBoostingClassifier(max_iter=200, early_stopping=False, random_state=0).fit(X[tr][:,cs], Y[tr])
        r["HGB_"+arm] = c._auc(yte, h.predict_proba(Xte[:,cs])[:,1])
    r["flow_count"] = c._auc(yte, Xte[:,ix["flow_count"]])
    r["persist"] = None if cur is None else c._auc(yte, cur+1e-9*Xte[:,ix["flow_count"]])
    rows[held]=r; print(held, {k:(round(v,3) if isinstance(v,float) else v) for k,v in r.items()}, flush=True)
df = pd.DataFrame(rows).T
df.to_csv(OUT/"lodo_hgb.csv"); print(df.round(3).to_string())
print("mean/sd HGB_all over days", df["HGB_all"].astype(float).mean().round(3), df["HGB_all"].astype(float).std().round(3))
