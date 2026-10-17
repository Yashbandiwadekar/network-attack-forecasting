import pandas as pd, numpy as np
P = "V:/Datasets/CIC-IDS-2018-flows/"
files = {"02-15":"Thursday-15-02-2018","02-16":"Friday-16-02-2018","02-22":"Thursday-22-02-2018","02-23":"Friday-23-02-2018","03-01":"Thursday-01-03-2018","02-28":"Wednesday-28-02-2018"}
for d,f in files.items():
    df = pd.read_csv(P+f+"_TrafficForML_CICFlowMeter.csv", usecols=["Timestamp","Label"], low_memory=False)
    df = df[df["Label"]!="Label"]
    ts = pd.to_datetime(df["Timestamp"], errors="coerce"); ok = ts.notna()
    df = df[ok]; ts = ts[ok]
    att = (df["Label"].str.strip().str.lower()!="benign")
    w = ts.dt.floor("10s")
    g = pd.DataFrame({"w":w,"att":att.values}).groupby("w").att.agg(["size","sum"])
    pos = g[g["sum"]>0]
    share = pos["sum"]/pos["size"]
    print(f"{d} flows={len(df)} attack_flows={int(att.sum())} ({att.mean():.3%}) windows={len(g)} pos_windows={len(pos)} | attack flows per pos window: median {pos['sum'].median():.0f}, share with <=2: {(pos['sum']<=2).mean():.2f}, <=5: {(pos['sum']<=5).mean():.2f} | attack share of window flows: median {share.median():.3f}, p10 {share.quantile(.1):.3f}, share of pos windows with attack<5% of flows: {(share<0.05).mean():.2f}; labels:", df['Label'].str.strip().value_counts().head(4).to_dict(), flush=True)
