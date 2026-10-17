from eval.diagnostics.harness import *
from eval.diagnostics.harness import build_train_caches, OUT, CACHE, ROOT
from eval.diagnostics import core as c
a = load(DS["cic18_test"]); y=(a["infiltration"][:,0]>0).astype(float); d=day_of(a); ix={n:i for i,n in enumerate(NAMES)}
for name in ["seed1","B_s3","Bplus_s3"]:
    model, scaler = get_model(name)
    for lab, fs in [("none",[]),("flow_count",["flow_count"]),("unique_dst_ports",["unique_dst_ports"]),("flow_count+unique_dst_ports",["flow_count","unique_dst_ports"]),("volume3",["flow_count","total_packets","total_bytes"]),("mean_duration",["mean_duration"]),("dur+iat",["mean_duration","mean_iat","var_iat","max_iat"])]:
        X=a["X"].copy()
        for f in fs: X[:,:,ix[f]]=scaler.mean[ix[f]]
        u=c.per_unit_auroc(y,score(model,scaler,X),d)
        print(f"{name:9s} ablate {lab:30s} pooled={u['pooled']:.3f} within="+" ".join(f"{k[5:]}:{v:.3f}" for k,v in u['within'].items()))
