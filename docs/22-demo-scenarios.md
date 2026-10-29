# 22. Demo scenarios

The Ingestion & Flows tab lists demo scenarios under the upload box. Each card loads a real, public capture that sits on the server, through
the same ingest path as an upload (`POST /api/v1/demo/load`; it replaces the dashboard's in-memory state exactly as an upload does and
returns 409 while a live/replay session is active). The cards come from `demo/demo_manifest.json` (`scenarios`); every number on a card is the
measured output of the served bundle (`dist/models/seed1`) on that exact file. The manifest's `documented_only` list is never served.

## How the demo slices were found (a search for the strongest alert)

The owner wanted the best-performing example of each attack family. So the slices were SEARCHED, not fixed in advance, and the winners are
optimistic examples by construction: the search is the selection. Do not read the cards as a detection rate. For per-family performance see docs/17.

`scripts/search_demo_slices.py` scores, in process on the served bundle, a fixed grid of slices of each family's day file:

* family = one attack label (the three web labels of a day are one family); span = first to last row of the family's labels;
* lengths 5,000 / 20,000 / 40,000 rows, end points evenly spaced across the span (pass 1: 5 points; pass 2: 12 points), plus the slice a fixed
  rule would have taken first (2,000 rows of context, 40,000 rows); slices kept only with at least 300 rows of the family's labels, at most
  15 MB, and some host with 12 windows (everything else is logged as skipped);
* score of a slice = the highest peak probability among hosts whose 12 scored windows contain observed, non-heuristic attack stages. An alert on
  all-Benign windows never counts. A family goes on the dashboard only if its best peak reaches the 0.40 alert threshold;
* the winner is rebuilt by `scripts/build_demo_files.py --from-search` and re-measured through `/api/v1/demo/load` on a separate local server (the
  numbers below are from that run and equal the search scores). Winners are also checked to make sure the scored windows contain the family's own
  flows: HOIC's best slice scored 0.7413 but its scored windows are the LOIC-UDP flows of the same slice, so it is excluded.

The model scores only each host's last 12 windows (2 minutes), so a short slice ending inside an attack is a legitimate way to show an alert. A
total of 525 slices were tried across 14 families (the full log is summarised per family in the manifest's `search`).

## Dashboard demos (measured on the exact files)

| demo | family | day | split tag (served config) | rows | size | peak | hosts flagged | scored windows (observed) |
|---|---|---|---|---|---|---|---|---|
| ftp-bruteforce-0214 | FTP brute force | 14 Feb 2018 | train day (in-sample) | 58942..63941 | 1.1 MB | 0.7044 | 1 of 1 | Initial Access x11, Benign x1 |
| dos-attacks-slowhttptest-0216 | DoS SlowHTTPTest | 16 Feb 2018 | held-out test day | 82470..87469 | 1.1 MB | 0.6245 | 1 of 1 | Impact x11, Benign x1 |
| ddos-attacks-loic-http-0220 | DDoS LOIC-HTTP | 20 Feb 2018 | train day (in-sample) | 413355..433354 | 8.4 MB | 0.9902 | 4 of 12 | Impact x12 |
| ddos-attack-loic-udp-0221 | DDoS LOIC-UDP | 21 Feb 2018 | train day (in-sample) | 0..4999 | 1.8 MB | 0.7413 | 1 of 1 | Impact x8, Benign x4 (interleaved) |
| infilteration-0301 | Infiltration | 1 Mar 2018 | held-out test day | 259655..264654 | 1.6 MB | 0.9207 | 1 of 1 | Lateral Movement x12 |
| benign | none (false-alarm check) | 23 Feb 2018 | held-out test day | 2402..37401 | 13.6 MB | 0.0093 | 0 of 1 | Benign x12 |

Total 27.7 MB (six files). Days without source IPs are one pseudo-host (`NETWORK-<date>`); 02-20 has real IPs, hence 12 hosts.
Days 02-14, 02-20, 02-21 are training days (config `split.train_days`), so those hits are in-sample; 02-16, 02-23, 03-01 are held-out test days.

## Families that did not make the dashboard (measured in the search, documented only)

"Best with attack in view" is the highest peak among scored slices whose scored windows contain the attack.

| family | day | tag | slices tried / scored | best with attack in view | highest peak in any window | why not shown |
|---|---|---|---|---|---|---|
| DoS Slowloris | 15 Feb 2018 | validation day | 43 / 32 | 0.3975 (rows 27925..32924) | 0.3975 | just below 0.40 |
| DoS GoldenEye | 15 Feb 2018 | validation day | 34 / 28 | 0.0725 | 0.1967 | never reaches 0.40 |
| DoS Hulk | 16 Feb 2018 | test day | 49 / 1 | none | 0.0856 | no Hulk slice within 15 MB gives a host 12 windows |
| DDoS HOIC | 21 Feb 2018 | train day | 49 / 1 | (0.7413, but the scored windows are LOIC-UDP flows) | 0.7413 | excluded, not HOIC's own windows; the other HOIC slices give no 12 windows within 15 MB |
| SSH brute force | 14 Feb 2018 | train day | 49 / 35 | 0.0071 | 0.1585 | never reaches 0.40 |
| Infiltration | 28 Feb 2018 | train day | 49 / 49 | none | 0.0884 | never reaches 0.40 with infiltration in view |
| Web attacks (brute force, XSS, SQLi) | 22 Feb 2018 | validation day | 3 / 3 | none | 0.1681 | attack rows are too few to fill a slice's last 12 windows |
| Web attacks | 23 Feb 2018 | test day | 3 / 2 | none | 0.0393 | same |
| Botnet / C2 | 2 Mar 2018 | train day | 48 / 47 | 0.0395 | 0.0395 | never reaches 0.40, even in-sample |

Earlier fixed-rule pass (start 2,000 rows before the family's first row, 40,000 rows; measured before the search was added): benign 0.009, SlowHTTPTest
0.592, LOIC-HTTP (30,000 rows) 0.652, FTP 0.614, infiltration 03-01 0.069, web attacks 0.033 (scored windows all Benign), botnet 0.031, CTU-13 scenario-6
PCAP 0.116 (cross-dataset, unlabelled, IPv4 TCP/UDP only). These are superseded by the search winners but are kept here as measured.
CIC-IDS-2017 (V:\Datasets\CIC-IDS-2017) was not used: its CSVs use different column names (`Total Fwd Packets`, ...) and the upload path rejects them.

## Sources and citation

* **CSE-CIC-IDS2018**, <https://www.unb.ca/cic/datasets/ids-2018.html>. Redistribution is allowed with citation (Sharafaldin, Habibi Lashkari, Ghorbani,
  "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization", ICISSP 2018 -- written from the CIC page convention,
  not found in this repo: check before publishing).
* **CTU-13** (Stratosphere Laboratory), <https://www.stratosphereips.org/datasets-ctu13>: no licence stated (Garcia et al., Computers & Security 45, 2014;
  same check-before-publishing note). CIC-IDS-2017 also states no licence. No CTU-13 or CIC-2017 data is in the demo set.

The data files are NOT in git (`demo/*` is ignored; only `demo/demo_manifest.json` is tracked). Keep the citation visible wherever the files are
served; the manifest carries it in each scenario's `source.citation`.

## Regenerate (on the machine that has the raw data)

```
python -m scripts.search_demo_slices --out <dir>/search_0.jsonl --ends 5            # pass 1 (and --ends 12 for pass 2); --shard/--shards to parallelise
python -m scripts.build_demo_files --out-dir <staging> --from-search <dir>/search_*.jsonl
# serve <staging> with the bundle on a spare port (PHOENIX_BUNDLE=dist/models/seed1, own PHOENIX_STATE_DIR, app.server.DEMO_DIR -> <staging>)
python -m scripts.build_demo_files --out-dir <staging> --measure --api http://127.0.0.1:<port>
python -m scripts.build_demo_files --out-dir <staging> --finalize                    # dashboard set -> demo/ , removes unused demo files
python -m scripts.build_demo_files --document-search <dir>/search_*.jsonl            # per-family outcome -> manifest
```

Files use LF line endings so the sha256 is OS independent; it depends on the pandas version that formatted the floats (recorded in the manifest).
Do not regenerate on the server: copy the files.

## Deploy

1. On the server: `git pull` first (this brings `demo/demo_manifest.json`; do not copy the manifest by hand beforehand or the pull refuses).
2. Copy only the data files from the dev PC into `<repo>/demo/`: the six `demo/demo-*.csv` (27.7 MB). Leave out the old `demo-capture-...` file.
3. Verify: `sha256sum demo/<file>` must equal that scenario's `sha256` in the manifest (the server re-checks at load and refuses a mismatch).
4. Build the dashboard (`npm run build --prefix frontend`, or copy `frontend/dist`; it is not in git, see docs/10) and restart the API the way it is run there.
5. A card whose file is missing shows "Not installed".
