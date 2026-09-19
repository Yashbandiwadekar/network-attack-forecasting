# GNN feature ablation (in progress)

Question: does adding graph-structure features from the GraphSAGE encoder
(`pipeline/graph_embedding_features.py`, 8 extra columns, encoder frozen at fixed random init)
improve forecasting over the same model without them?

Arms: **no-GNN** = `docs/04-evaluation-real-before-graph-embed.md` (33 features);
**frozen-GNN** = `docs/04-evaluation-real.md` (41 features). Same data, same split (194,632 test
sequences), same hyperparameters. Jointly-trained-GNN and CTU-13 arms are not run yet.

## Real CIC-IDS-2018: frozen-GNN vs no-GNN

| Metric | Transformer no-GNN | Transformer frozen-GNN | LSTM no-GNN | LSTM frozen-GNN |
|---|---|---|---|---|
| F1 @ 0.5 threshold | 0.920 | 0.917 | 0.896 | 0.908 |
| F1 @ 5% FPR budget | 0.503 | 0.535 | 0.554 | 0.535 |
| Stage macro-F1 | 0.841 | 0.820 | 0.569 | 0.715 |

Both LSTM columns are the LSTM baseline retrained on the respective feature vector.
Lead time for the Transformer is numerically identical in both runs (32 transitions, 0 missed,
46.9% detected early, mean +6.9s, median +0.0s).

## Verdict: no measurable benefit

- The Transformer moves by -0.003, +0.032, and -0.021 across the three metrics: mixed, small,
  and not consistently in one direction.
- The LSTM moves +0.012, -0.019, and +0.146. The large stage-F1 jump is the only big change, and
  it goes to the baseline, not the world model. It narrows the Transformer-vs-LSTM stage gap
  from 0.272 to 0.105, which weakens (not strengthens) the "self-attention specifically matters"
  claim from the earlier benchmark.
- Each number is a single training run with no repeated seeds, so run-to-run variance is unknown.
  Differences of a few hundredths are within what seed noise could plausibly produce. Nothing
  here should be reported as a graph-feature win.
- The identical lead-time result is most likely a coincidence of a coarse metric (32 events,
  10-second steps), not evidence the rollout is unchanged. It is not evidence either way.

## Why this test was structurally weak

9 of the 10 CIC-IDS-2018 days have no real IP addresses; windowing falls back to one pseudo-host
per day, and every graph feature (scalar and embedding) is zero-filled there
(`has_ip_data = 0`). Graph structure can only carry signal on the single day with real IPs, so
a null result here says little about graph features in general. CTU-13, where every scenario has
real IPs, is the fairer test and has not been run yet.

Persistence and the Markov chain still beat every learned model at the immediate next step
(F1 0.988), as already documented in `docs/04-evaluation-real.md`.

## Still to do

- CTU-13 rebuild, retrain, and the same comparison.
- Jointly-trained GNN arm (`models/train_joint.py`, code complete and smoke-tested on synthetic
  data only).
- Repeated seeds, so differences can be judged against noise.
