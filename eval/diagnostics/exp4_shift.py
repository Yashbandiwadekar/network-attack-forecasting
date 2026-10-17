from eval.diagnostics.harness import *
from eval.diagnostics.harness import build_train_caches, OUT, CACHE, ROOT
build_train_caches()
from eval.diagnostics import core as c
import pandas as pd
pd.set_option("display.width", 300); pd.set_option("display.max_columns", 40); pd.set_option("display.max_rows", 100)
ix = {n:i for i,n in enumerate(NAMES)}
show = ["flow_count","unique_dst_ports","total_bytes","total_packets","mean_duration","mean_iat","var_iat","max_iat","bidir_ratio","tcp_ratio","udp_ratio","rst_ratio","psh_ratio"]
sets = {}
for k in ["cic18_val","cic18_test","ctu_contig","unsw_contig","cic17_60s"]:
    a = load(DS[k]); sets[k] = a["X"]
    if k in ("cic18_val","cic18_test"):
        d = day_of(a)
        for u in np.unique(d): sets[u[5:]] = a["X"][d==u]
tl = np.load(CACHE/"train_last.npz", allow_pickle=False)
for tag, cfgp in [("seed1","configs/real_data_v2_converged_seed1.yaml"),("B","configs/joint_v3_B.yaml")]:
    sc = FeatureScaler.load(resolve_path(load_config(cfgp),"processed_dir")/"scaler.npz")
    print("\n##", tag, "scaler mean/std for key features")
    print(pd.DataFrame({"mean":sc.mean[[ix[f] for f in show]],"std":sc.std[[ix[f] for f in show]]}, index=show).round(3).T.to_string())
    rows = {k: dict(zip(show, c.clip_rates(X, sc.mean, sc.std)[[ix[f] for f in show]])) for k,X in sets.items()}
    print("clip rate (|z|>6) by dataset:"); print(pd.DataFrame(rows).T.round(3).to_string())
    zs = {k: dict(zip(show, ((X.reshape(-1,41).mean(0)-sc.mean)/sc.std)[[ix[f] for f in show]])) for k,X in sets.items()}
    print("mean z (unclipped) by dataset:"); print(pd.DataFrame(zs).T.round(2).to_string())
# medians of raw
print("\nraw medians (last window):")
med = {k: dict(zip(show, np.median(X[:,-1,:],axis=0)[[ix[f] for f in show]])) for k,X in sets.items()}
med["train02-20"] = dict(zip(show, np.median(tl["Xlast"][tl["day"]=="2018-02-20"],axis=0)[[ix[f] for f in show]]))
med["train_pseudo"] = dict(zip(show, np.median(tl["Xlast"][tl["hasip"]==0],axis=0)[[ix[f] for f in show]]))
print(pd.DataFrame(med).T.round(3).to_string())
# duration / timeout effects
print("\nshare of windows with mean_duration >= 10s / >= 60s / >=100s (flow records extend past the window):")
for k,X in sets.items():
    md = X[:,-1,ix["mean_duration"]]
    print(f"{k:12s} n={len(md):7d} >=10s {np.mean(md>=10):.3f} >=60s {np.mean(md>=60):.3f} >=100s {np.mean(md>=100):.3f} median {np.median(md):.3f}")
for nm,m in [("train02-20",tl["day"]=="2018-02-20"),("train_pseudo",tl["hasip"]==0)]:
    md = tl["Xlast"][m][:,ix["mean_duration"]]
    print(f"{nm:12s} n={len(md):7d} >=10s {np.mean(md>=10):.3f} >=60s {np.mean(md>=60):.3f} >=100s {np.mean(md>=100):.3f} median {np.median(md):.3f}")
# SMD / KS of test vs train (last window, seed1 train)
print("\nSMD vs seed1 train (z units of train std) for last-window; ks")
ref = tl["Xlast"]
r = {}
for k in ["cic18_test","ctu_contig","unsw_contig","cic17_60s"]:
    X = sets[k][:,-1,:]
    o = c.smd_and_ks(ref, X, max_n=100000)
    r[k+" smd"] = pd.Series(o["smd"], index=NAMES); r[k+" ks"] = pd.Series(o["ks"], index=NAMES)
print(pd.DataFrame(r).loc[show].round(2).to_string())
