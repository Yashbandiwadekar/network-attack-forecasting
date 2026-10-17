from eval.diagnostics.harness import *
from eval.diagnostics.harness import build_train_caches, OUT, CACHE, ROOT
from eval.diagnostics import core as c
import pandas as pd
ix = {n:i for i,n in enumerate(NAMES)}
data = {k: load(DS[k]) for k in ["ctu_contig","unsw_contig","cic17_60s"]}
G = {"graph_ident":["has_ip_data","unique_dst_ips","graph_out_degree","graph_fan_out_ratio","graph_fan_in_ratio","graph_component_size","graph_dst_entropy"]+[f"graph_embed_{i}" for i in range(8)],
     "proto":["tcp_ratio","udp_ratio"], "volume":["flow_count","total_packets","total_bytes","unique_dst_ports"],
     "dur":["mean_duration","mean_iat","var_iat","max_iat"], "flags":["syn_ratio","ack_ratio","fin_ratio","rst_ratio","psh_ratio","urg_ratio"], "bidir":["bidir_ratio"]}
combos = {"ident+proto":["graph_ident","proto"], "ident+proto+flags":["graph_ident","proto","flags"], "ident+proto+flags+dur":["graph_ident","proto","flags","dur"],
          "all_but_volume_and_bidir":["graph_ident","proto","flags","dur"], "everything":list(G)}
def hostauc(y, p, ips):
    import pandas as pd
    df = pd.DataFrame({"ip":ips,"y":y,"p":p}).groupby("ip").agg(y=("y","max"),p=("p","mean"), pm=("p","max"))
    return c.per_unit_auroc(df["y"].values, df["p"].values, np.zeros(len(df)))["pooled"], len(df), int(df["y"].sum())
def boot_host(y,p,ips,B=500,seed=0):
    df = pd.DataFrame({"ip":ips,"y":y,"p":p})
    hosts = df.groupby("ip").agg(y=("y","max"),p=("p","mean"))
    rng = np.random.default_rng(seed); vals=[]
    pos = hosts.index[hosts.y==1].values; neg = hosts.index[hosts.y==0].values
    for _ in range(B):
        a = rng.choice(pos,len(pos)); b = rng.choice(neg,len(neg))
        yy = np.r_[np.ones(len(a)),np.zeros(len(b))]; pp = np.r_[hosts.loc[a,"p"].values,hosts.loc[b,"p"].values]
        vals.append(c._auc(yy,pp))
    return np.percentile(vals,[2.5,97.5]).round(3).tolist()
for name in ["seed1","B_s3","Bplus_s1"]:
    model, scaler = get_model(name)
    for k,a in data.items():
        y=(a["infiltration"][:,0]>0).astype(float); X=a["X"]; ips=a["src_ip"].astype(str)
        p0 = score(model,scaler,X)
        h,nh,npos = hostauc(y,p0,ips)
        print(f"{name:9s} {k:11s} seq-AUROC={c._auc(y,p0):.3f} host-level AUROC={h:.3f} (hosts={nh}, pos hosts={npos}) 95%CI host-bootstrap={boot_host(y,p0,ips)}", flush=True)
        if k=="cic17_60s": continue
        r = {}
        for cn, gs in combos.items():
            X2 = X.copy()
            for g in gs:
                for f in G[g]: X2[:,:,ix[f]] = scaler.mean[ix[f]]
            r[cn] = round(c._auc(y,score(model,scaler,X2)),3)
        print("     combined mean-ablation:", r, flush=True)
