from eval.diagnostics.harness import *
from eval.diagnostics.harness import build_train_caches, OUT, CACHE, ROOT
from eval.diagnostics import core as c
import pandas as pd
pd.set_option("display.width", 300); pd.set_option("display.max_columns", 40); pd.set_option("display.max_rows", 100)
data = {k: load(DS[k]) for k in ["cic18_test","ctu_contig","unsw_contig","cic17_60s"]}
ix = {n:i for i,n in enumerate(NAMES)}
groups = {
 "volume": ["flow_count","total_packets","total_bytes"],
 "has_ip": ["has_ip_data"],
 "dst_div": ["unique_dst_ports","unique_dst_ips"],
 "graph": ["graph_out_degree","graph_fan_out_ratio","graph_fan_in_ratio","graph_component_size","graph_dst_entropy"],
 "graph_embed": [f"graph_embed_{i}" for i in range(8)],
 "all_graph+hasip+dstips": ["has_ip_data","unique_dst_ips","graph_out_degree","graph_fan_out_ratio","graph_fan_in_ratio","graph_component_size","graph_dst_entropy"]+[f"graph_embed_{i}" for i in range(8)],
 "duration_iat": ["mean_duration","mean_iat","var_iat","max_iat"],
 "tcp_flags": ["syn_ratio","ack_ratio","fin_ratio","rst_ratio","psh_ratio","urg_ratio"],
 "proto": ["tcp_ratio","udp_ratio"],
 "bidir": ["bidir_ratio"],
}
single = ["flow_count","total_packets","total_bytes","mean_duration","unique_dst_ports","tcp_ratio","udp_ratio","bidir_ratio","mean_iat","var_iat","max_iat","rst_ratio","psh_ratio","syn_ratio","ack_ratio","fin_ratio"]
out = {}
for name in ["seed1","B_s3","Bplus_s1"]:
    model, scaler = get_model(name)
    rows = {}
    for k,a in data.items():
        y=(a["infiltration"][:,0]>0).astype(float); X=a["X"]
        base = c.per_unit_auroc(y, score(model,scaler,X), np.zeros(len(y)))["pooled"]
        r = {"base": base}
        for g,fs in list(groups.items())+[(f,[f]) for f in single]:
            X2 = X.copy()
            for f in fs: X2[:,:,ix[f]] = scaler.mean[ix[f]]
            r[g] = c.per_unit_auroc(y, score(model,scaler,X2), np.zeros(len(y)))["pooled"]
        # permute (rows) volume group jointly
        rng = np.random.default_rng(0); perm = rng.permutation(len(X)); X2 = X.copy()
        for f in groups["volume"]: X2[:,:,ix[f]] = X[perm][:,:,ix[f]]
        r["perm_volume"] = c.per_unit_auroc(y, score(model,scaler,X2), np.zeros(len(y)))["pooled"]
        rows[k] = r
    df = pd.DataFrame(rows).round(3); out[name]=df
    print("\n=== ", name, "AUROC after mean-ablating group/feature (base in first row)"); print(df.to_string(), flush=True)
    df.to_csv(OUT/f"ablate_{name}.csv")
