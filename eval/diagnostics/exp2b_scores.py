from eval.diagnostics.harness import *
from eval.diagnostics.harness import build_train_caches, OUT, CACHE, ROOT
from eval.diagnostics import core as c
from scipy.stats import spearmanr
import pandas as pd
pd.set_option("display.width", 300); pd.set_option("display.max_columns", 40); pd.set_option("display.max_rows", 100)
data = {k: load(DS[k]) for k in ["cic18_test","ctu_contig","unsw_contig","cic17_60s"]}
ix = {n:i for i,n in enumerate(NAMES)}
# host/label structure
for k in ["ctu_contig","unsw_contig","cic17_60s"]:
    a = data[k]; y = (a["infiltration"][:,0]>0)
    ips = a["src_ip"].astype(str)
    df = pd.DataFrame({"ip":ips,"y":y})
    g = df.groupby("ip").y.agg(["size","mean"])
    print(k, "hosts", len(g), "hosts with 0<pos<1:", int(((g["mean"]>0)&(g["mean"]<1)).sum()), "pure-pos hosts", int((g["mean"]==1).sum()), "pure-neg", int((g["mean"]==0).sum()), "hosts with any pos", int((g["mean"]>0).sum()))
    if "scenario_id" in a: print("   scenarios", len(np.unique(a["scenario_id"])))
    print(g.sort_values("mean",ascending=False).head(12).to_string())
# score stats & correlation
res = {}
for name in ["seed1","B_s3","B_s1","Bplus_s1","Bplus_s3"]:
    model, scaler = get_model(name)
    for k,a in data.items():
        p = score(model, scaler, a["X"]); y=(a["infiltration"][:,0]>0).astype(float)
        last = a["X"][:,-1,:]
        sp = {f: spearmanr(p, last[:,ix[f]]).correlation for f in ["flow_count","total_packets","total_bytes","mean_duration","unique_dst_ports","tcp_ratio"]}
        print(f"{name:9s} {k:11s} AUROC={c.per_unit_auroc(y,p,np.zeros(len(y)))['pooled']:.3f} score med={np.median(p):.3f} p90={np.percentile(p,90):.3f} frac>0.4={np.mean(p>=0.4):.3f} spearman " + " ".join(f"{f[:8]}={v:+.2f}" for f,v in sp.items()), flush=True)
