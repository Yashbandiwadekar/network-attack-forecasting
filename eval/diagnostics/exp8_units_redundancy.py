from eval.diagnostics.harness import *
from eval.diagnostics.harness import build_train_caches, OUT, CACHE, ROOT
from eval.diagnostics import core as c
import pandas as pd
ix = {n:i for i,n in enumerate(NAMES)}
def episodes(t, cur, merge_gap=6, step_s=10):
    # t: datetime64 sorted, cur: 0/1 current-window label per row (windows are rows). count runs of positives merged if < merge_gap benign windows (by time)
    t = t.astype("datetime64[s]").astype(np.int64)
    pos_t = t[cur>0]
    if len(pos_t)==0: return 0, 0
    gaps = np.diff(pos_t)/step_s - 1   # benign (missing) windows between consecutive positive windows
    return int((gaps>=merge_gap).sum()+1), len(pos_t)
rows = []
tr = load("data/processed_real_v2_converged:train")
va = load(DS["cic18_val"]); te = load(DS["cic18_test"])
for split, a in [("train",tr),("val",va),("test",te)]:
    d = day_of(a)
    for u in np.unique(d):
        m = d==u
        ips = a["src_ip"][m]; t = a["window_end_time"][m]; cur = a["current_infiltration"][m]
        # unique windows: one row per window per host; rows are windows (end of input)
        eps=0; npos=0; nh=0
        for ip in np.unique(ips):
            mm = ips==ip; o = np.argsort(t[mm]); e,n = episodes(t[mm][o], cur[mm][o]); eps+=e; npos+=n; nh+=1 if n>0 else 0
        rows.append((split,u,m.sum(),len(np.unique(ips)),nh,eps,npos))
df = pd.DataFrame(rows, columns=["split","day","seq","hosts","hosts_with_attack","episodes(merge6)","pos_windows"])
print(df.to_string())
# redundancy / constants on pseudo-host days and on 02-20
d = day_of(tr); hasip = tr["X"][:,-1,3]
for nm, m in [("02-20 (real IP)", hasip==1), ("pseudo-host days (train)", hasip==0)]:
    Xs = tr["X"][m][::max(1,int(m.sum()//50000)),-1,:]
    print("\n##", nm, "n=", len(Xs))
    const = c.constant_features(Xs); print("constant:", [NAMES[i] for i in np.where(const)[0]])
    ne = [(NAMES[i], round(float(Xs[:,i].std()),3)) for i in range(41) if not const[i]]
    pairs = c.high_corr_pairs(Xs, NAMES, 0.9)
    print("near-const (>=99% one value):", [NAMES[i] for i in range(41) if (not const[i]) and (np.unique(Xs[:,i],return_counts=True)[1].max()/len(Xs)>=0.99)])
    print("pairs |r|>=0.9:", [(a,b,round(r,3)) for a,b,r in pairs])
# attack-flow dilution: how big is a positive window relative to benign background? flow_count by label on pseudo days
for nm,a in [("val",va),("test",te)]:
    d = day_of(a)
    for u in np.unique(d):
        m=d==u; y=a["infiltration"][m,0]>0; fc=a["X"][m][:,-1,ix["flow_count"]]
        print(nm,u,"flow_count median benign-next %.0f pos-next %.0f ; unique_dst_ports median %.0f / %.0f"%(np.median(fc[~y]),np.median(fc[y]),np.median(a['X'][m][:,-1,ix['unique_dst_ports']][~y]),np.median(a['X'][m][:,-1,ix['unique_dst_ports']][y])))
