from eval.diagnostics.harness import *
from eval.diagnostics.harness import build_train_caches, OUT, CACHE, ROOT
from eval.diagnostics import core as c
import torch.nn.functional as F
out = {}
data = {k: load(DS[k]) for k in ["cic18_val","cic18_test"]}
for name in MODELS:
    for which in ["best","final"]:
        model, scaler = get_model(name, which)
        dev = next(model.parameters()).device
        for dk, arr in data.items():
            p = score(model, scaler, arr["X"])
            y = (arr["infiltration"][:,0] > 0).astype(float)
            r = c.per_unit_auroc(y, p, day_of(arr))
            # val-loss decomposition
            X = torch.tensor(scaler.transform(arr["X"]), dtype=torch.float32, device=dev)
            ns = torch.tensor(scaler.transform(arr["next_state"]), dtype=torch.float32, device=dev)
            fs = torch.tensor(arr["future_stages"][:,0], device=dev)
            inf = torch.tensor(arr["infiltration"][:,0], dtype=torch.float32, device=dev)
            with torch.no_grad():
                pn, sl, il = model(X)
                mse = F.mse_loss(pn, ns).item()
                m = fs != -1
                ce = F.cross_entropy(sl[m], fs[m]).item()
                bce = F.binary_cross_entropy_with_logits(il, inf).item()
                mse_feat = ((pn-ns)**2).mean(0).cpu().numpy()
            r["loss"] = {"mse": mse, "ce": ce, "bce": bce, "total": mse+ce+bce}
            r["mse_per_feature_top"] = sorted(zip(NAMES, mse_feat.tolist()), key=lambda t:-t[1])[:5]
            out[f"{name}|{which}|{dk}"] = r
            w = {k: (None if v is None else round(v,3)) for k,v in r["within"].items()}
            print(f"{name:8s} {which:5s} {dk:10s} pooled={r['pooled']:.3f} daymean={r['unit_mean']:.3f} meanwithin={r['mean_within']:.3f} within={w} loss mse={mse:.3f} ce={ce:.3f} bce={bce:.3f}", flush=True)
json.dump(out, open(OUT/"exp1_perday.json","w"), indent=1, default=float)
