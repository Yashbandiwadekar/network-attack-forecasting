// Rebuilds the SIH 26153 idea submission with the factual corrections.
// Every figure here is traceable to a file in this repository; see docs/ and BUILD_REPORT.md.
const { Document, Packer, Paragraph, TextRun, AlignmentType } = require('docx');
const fs = require('fs');

const P = (text) => new Paragraph({
  children: [new TextRun(text)],
  spacing: { after: 160, line: 276 },
  alignment: AlignmentType.JUSTIFIED,
});

const body = [];

body.push(new Paragraph({
  children: [new TextRun({ text: 'Idea Title', bold: true })],
  spacing: { after: 80 },
}));
body.push(P('AI-Based Network Attack Forecasting Using Explainable World Model Dynamics'));

body.push(new Paragraph({
  children: [new TextRun({ text: 'Idea Description', bold: true })],
  spacing: { before: 200, after: 80 },
}));

body.push(P(
  'Phoenix IDPS forecasts how a network attack will progress, rather than classifying traffic that has already ' +
  'arrived. A conventional intrusion detection system answers one question: is this flow malicious? That question ' +
  'is answered after the fact, and it treats every flow as independent. Real intrusions are not independent events. ' +
  'An attacker probes, gains a foothold, moves laterally, establishes a command channel, and only then takes data. ' +
  'Any single connection in that chain can look ordinary. The chain does not.'
));

body.push(P(
  'The system learns the transition dynamics of a network, written as P(S_t+1 | S_t-L..S_t), and rolls those ' +
  'dynamics forward. Given the last twelve ten-second windows of a host’s behaviour, it predicts the next six ' +
  'windows: a sixty-second forecast, with an infiltration probability and a MITRE ATT&CK stage at every step. The ' +
  'model is a Transformer encoder. That choice was made for two reasons. The problem is temporal, and attention ' +
  'weights double as an explanation of which past windows drove a given prediction. A graph neural network was ' +
  'considered and rejected for this iteration because it would require explicit graph construction on top of an ' +
  'already multi-stage pipeline.'
));

body.push(P(
  'Traffic is first reduced to ten-second windows per source host. Each window carries 41 features in four groups: ' +
  '19 flow-level statistics such as packet and byte counts, durations, TCP flag counts and inter-arrival times; ' +
  '5 graph-level features describing how many distinct peers and ports a host touched; 8 learned graph-embedding ' +
  'features summarising the host’s position in the communication graph; and 9 packet-level features. Twelve ' +
  'consecutive windows form one input sequence, so the model sees two minutes of history before it predicts ' +
  'anything.'
));

body.push(P(
  'The world model is a small Transformer encoder: 3 layers, 4 attention heads, 64-dimensional embeddings. It is ' +
  'deliberately small. The dataset is large but the number of genuinely distinct attack episodes in it is not, and ' +
  'a larger model would memorise rather than generalise. Training predicts a single step, t to t+1. Forecasting is ' +
  'what turns that into a world model: the predicted next state is appended to the window, the oldest window is ' +
  'dropped, and the model is run again, six times. Each step emits an infiltration probability, a stage ' +
  'distribution over the MITRE vocabulary, attention weights, and the magnitude of the state change it expects.'
));

body.push(P(
  'CIC-IDS-2018 provides roughly sixteen million labelled flows across ten days, processed here into 1,479,555 ' +
  'windows and 1,256,931 sequences, split 1,239,090 train / 6,685 validation / 7,191 test. The split is ' +
  'day-disjoint: whole days are assigned to one side or the other, so no attack session is ever split across ' +
  'training and test.'
));

body.push(P(
  'One property of the dataset shapes every result that follows, and it is worth stating plainly rather than ' +
  'discovering later. Nine of the ten days ship without source and destination IP addresses. Those days collapse ' +
  'to a single network-wide pseudo-host each, because there is no way to attribute a flow to a machine. Only the ' +
  'DDoS day retains real per-host structure. This is why leave-one-attack-family-out succeeds marginally on impact ' +
  'and fails on the other three families: those families have no real per-host data to learn host-level ' +
  'progression from. The limitation belongs to the dataset, not to the architecture, and the fix is a dataset with ' +
  'the 5-tuple intact on every day. CIC-IDS-2017 keeps it, and moving to it is the next step.'
));

body.push(P(
  'The model is trained and evaluated on real CIC-IDS-2018 traffic, roughly sixteen million flows across ten days. ' +
  'Results below are the mean and standard deviation of three independent training runs on a day-disjoint split, ' +
  'meaning no attack session appears in both training and test.'
));

body.push(P(
  'Precision is 0.931 ± 0.024 at the 0.5 threshold on 7,191 held-out sequences, of which 1,482 are positive. ' +
  'AUROC is 0.794 ± 0.043 and AUPRC 0.646 ± 0.035. Recall is 0.325 ± 0.029 and F1 0.481 ± 0.033.'
));

body.push(P(
  'Precision is the side that matters operationally. When this system raises an alarm it is right about ninety-three ' +
  'times in a hundred, which speaks directly to alert fatigue, the reason most detection tooling gets ignored in ' +
  'practice. Recall is the weak side and is stated as such: roughly two in three attack windows go unflagged. ' +
  'Phoenix IDPS is a second signal beside existing detection, not a replacement for it.'
));

body.push(P(
  'An earlier version of this project reported F1 0.917. An internal audit found that the split cut train and test ' +
  'per host in time order, so both sides shared the same attack sessions. That is data snooping in the sense of Arp ' +
  'et al., "Dos and Don’ts of Machine Learning in Computer Security" (USENIX Security 2022). The result was ' +
  'withdrawn, the split was rebuilt day-disjoint, and everything was re-measured. A second figure, a ' +
  'leave-one-family-out AUROC of 0.432 that appeared to show the model performing worse than chance, turned out to ' +
  'be a single-seed artefact and was also withdrawn once three seeds were run. The full audit trail, including both ' +
  'retractions, is published in the repository.'
));

body.push(P(
  'This is stated up front because a project that only reports its best number is difficult to trust. The numbers ' +
  'above are lower than the ones this project started with, and they are the ones that survived scrutiny.'
));

body.push(P(
  'The limits are as important as the results, so they are stated with their measurements rather than left for a ' +
  'reader to find. Generalisation to unseen attack families is not demonstrated. Leave-one-attack-family-out, ' +
  'three seeds per fold, gives AUROC 0.685 ± 0.087 for initial access, 0.528 ± 0.129 for lateral ' +
  'movement, 0.646 ± 0.131 for command and control, and 0.819 ± 0.128 for impact. Only impact is ' +
  'distinguishable from chance, and only marginally. Zero-shot transfer to CTU-13 fails outright at AUROC 0.517, ' +
  'which is chance; that matches the published literature on cross-dataset intrusion detection rather than ' +
  'contradicting it.'
));

body.push(P(
  'The system also does not warn early, despite being a forecaster. Measured lead time across 628 ' +
  'benign-to-attack transitions is −0.5 seconds mean and +0.0 seconds median, so it alarms at onset, ' +
  'fractionally late, rather than before. The headline figures are one-step, ten-second measurements. A ' +
  'frozen-state ablation showed that holding the first-step estimate across the full minute scores slightly higher ' +
  'than advancing the model’s state, AUROC 0.785 against 0.755 at t+60s. The rollout produces the trajectory, ' +
  'the per-step stages and the counterfactual path, but it does not improve infiltration ranking at longer ' +
  'horizons. Finally, packet-level features are implemented and unit-tested, but no CIC-IDS-2018 packet capture ' +
  'was obtained at 37 GB per day, so the shipped model is flow-only and the nine packet features are zero-filled. ' +
  'The dataset metadata records this as flow_only: true rather than leaving it implied.'
));

body.push(P(
  'Every forecast carries its evidence. The served explainability endpoint returns gradient-times-input attributions ' +
  'over the model’s own 41-feature vector, alongside the Transformer’s attention weights over the input ' +
  'windows, so an analyst sees both which features drove the score and which moments in the recent past the model ' +
  'weighted. A KernelSHAP explainer is also implemented for slower, model-agnostic attribution. Predictions are ' +
  'never presented as bare numbers.'
));

body.push(P(
  'The MITRE ATT&CK mapping is treated as a documented heuristic, not ground truth. CIC-IDS-2018 labels do not map ' +
  'one to one onto the stage vocabulary. Three stages have real data behind them. Reconnaissance is derived from a ' +
  'port-scan signal that depends on a packet-level feature, so on the shipped flow-only checkpoints that override ' +
  'never fires, and exfiltration has no real-data label at all. Both facts are surfaced in the interface: any stage ' +
  'produced by a rule rather than the trained classifier is labelled as such on screen.'
));

body.push(P(
  'Every alert shown to an analyst is appended to an append-only SHA-256 hash chain, each record folding in the ' +
  'previous record’s hash, so a prediction cannot be quietly altered or deleted after the fact. The chain ' +
  'verifies on read and reports the first bad index if it has been tampered with. Reportable incidents are drafted ' +
  'against CERT-In’s six-hour disclosure window, with the category, the deadline and a live countdown, ' +
  'generated entirely offline.'
));

body.push(P(
  'Latency was measured on the deployed pipeline using real captured traffic, not synthetic input. Interactive ' +
  'analysis of a host, meaning the forecast plus its explanation, completes in 9.9 ms. Scoring every host in a batch ' +
  'costs 0.012 ms per host, so 5,000 hosts are scored in 60 ms: a full sixty-second forecast for every host on a ' +
  'mid-sized network finishes inside a single ten-second window. Ingesting and feature-building a 120,000-flow ' +
  'capture takes about two seconds and happens once per upload.'
));

body.push(P(
  'The system runs fully offline with no cloud API calls at any stage, which matters because traffic captures are ' +
  'sensitive and often cannot leave the environment that produced them. A React dashboard is served by the same ' +
  'FastAPI process that runs the model, on one port, so a demonstration on an isolated network needs no ' +
  'configuration beyond choosing the address to bind. Input is a PCAP, a PCAPNG or a CICFlowMeter CSV; PCAP has no ' +
  'schema requirement because flow records are derived from the packets directly. A host is scored once it has two ' +
  'minutes of traffic, which is the twelve consecutive windows the model needs.'
));

body.push(P(
  'The Transformer is benchmarked against logistic regression on both stacked and last-window inputs, an LSTM, a ' +
  'Markov chain over the label sequence, and a persistence baseline. The last two read the current window’s ' +
  'true label and are reported as label oracles, because a deployed system never has that information; naming them ' +
  'as oracles keeps the comparison honest. The reason for benchmarking at all is that a more complex architecture ' +
  'needs a reason to exist. The project also ships an adversarial evasion test: a white-box PGD attack does defeat ' +
  'the probability head by suppressing volume features, the threat model under which that matters is stated ' +
  'explicitly, and a second reconstruction-error gate recovers the alarm at a measured 1.06% false-positive cost. ' +
  'The codebase carries 349 automated backend tests and 13 frontend tests.'
));

body.push(P(
  'Most published intrusion-detection work does not test for evasion at all. This project does, and reports a ' +
  'failure. A white-box projected-gradient attack that perturbs only the most recent window drives the infiltration ' +
  'probability from 0.9975 to 0.0000 inside a 1.5-standard-deviation budget. The threat model matters, so it is ' +
  'stated rather than implied: the features the attack pushes hardest are flow count, total packets and total ' +
  'bytes, all downward. The model has learned that volume means attack, and evading it requires genuinely sending ' +
  'less. For a flood or a brute-force campaign that defeats the attack’s own purpose. For a low-and-slow ' +
  'intrusion that was never volume-heavy, it is a real weakness, and this dataset contains no real examples of that ' +
  'case. A second gate based on reconstruction error, asking whether the observed window matches what the ' +
  'model’s own dynamics predicted, recovers the alarm on this attack at a measured 1.06% false-positive cost. ' +
  'It is reported as evidence, not as a fix.'
));

body.push(P(
  'The results above exist because the project was audited against itself rather than only demonstrated. Findings ' +
  'were written as numbered work orders with binding acceptance criteria: an item counts as fixed only when its ' +
  'check has been run and the actual output pasted into the build report. That process is what produced the two ' +
  'retractions, the day-disjoint rebuild, the seeded re-measurement, the false-alarm accounting on the lead-time ' +
  'metric, and the frozen-state ablation. Several findings remain open and are listed as open. The audit document ' +
  'is part of the deliverable, not an internal artefact.'
));

body.push(P(
  'Phoenix IDPS is a forecasting layer that sits on top of network telemetry and answers a different question from ' +
  'the one a classifier answers. It is not a finished commercial product, and the limitations above are real. What ' +
  'it demonstrates is that attack progression can be modelled as a temporal prediction problem, that the resulting ' +
  'forecasts can be explained rather than asserted, and that a system making security claims can publish the ' +
  'measurements that test them, including the ones that did not go its way.'
));

body.push(new Paragraph({
  children: [new TextRun({ text: 'Idea Abstract', bold: true })],
  spacing: { before: 300, after: 80 },
}));

body.push(P(
  'Phoenix IDPS forecasts network attack progression instead of classifying traffic after it arrives. It learns ' +
  'network state-transition dynamics, P(S_t+1 | S_t-L..S_t), with a Transformer world model and rolls them forward ' +
  'six steps of ten seconds to produce a sixty-second forecast: an infiltration probability and a MITRE ATT&CK stage ' +
  'at each step, with an explanation attached. Intrusions unfold as sequences, and a connection that looks ordinary ' +
  'alone can be meaningful in context; modelling the sequence is the point.'
));

body.push(P(
  'On real CIC-IDS-2018 traffic, evaluated across three seeds on a day-disjoint split where no attack session is ' +
  'shared between training and test, it reaches precision 0.931 ± 0.024 and AUROC 0.794 ± 0.043 on 7,191 ' +
  'held-out sequences. High precision is the operationally useful property: what it flags is almost always real, ' +
  'which is what makes an alert worth reading. Recall is 0.325, so it misses most attack windows and is positioned ' +
  'as a second signal beside existing detection rather than a replacement.'
));

body.push(P(
  'An earlier F1 of 0.917 was withdrawn after an internal audit found the split shared attack sessions between train ' +
  'and test, data snooping in the sense of Arp et al. (USENIX Security 2022). It was re-measured day-disjoint, and a ' +
  'second single-seed figure was withdrawn once three seeds were run. Generalisation to unseen attack families is ' +
  'not demonstrated: leave-one-family-out is indistinguishable from chance on three of four families, and zero-shot ' +
  'transfer to CTU-13 is 0.517. Measured lead time is −0.5 s, so the system alarms at onset rather than ahead ' +
  'of it. These results are published alongside the positive ones.'
));

body.push(P(
  'Traffic is reduced to ten-second windows per host, each carrying 41 features across four groups: 19 flow ' +
  'statistics, 5 graph-level counts, 8 learned graph-embedding features and 9 packet-level features. Twelve ' +
  'consecutive windows form the input, so the model sees two minutes of history before predicting. The world ' +
  'model itself is small on purpose, 3 layers and 4 attention heads, because the dataset holds many flows but few ' +
  'genuinely distinct attack episodes. One dataset property shapes every result: nine of the ten CIC-IDS-2018 days ' +
  'ship without IP addresses and collapse to one network-wide pseudo-host each, leaving only the DDoS day with ' +
  'real per-host structure. That is why family generalisation fails on three of four families, and why moving to ' +
  'CIC-IDS-2017, which keeps the 5-tuple on every day, is the next step.'
));

body.push(P(
  'The project also tests for adversarial evasion, which most published intrusion-detection work does not. A ' +
  'white-box PGD attack drives the infiltration probability from 0.9975 to 0.0000 by suppressing volume features. ' +
  'The threat model is stated rather than implied: evading this way means genuinely sending less traffic, which ' +
  'defeats a flood but not a low-and-slow intrusion. A second reconstruction-error gate recovers the alarm at a ' +
  'measured 1.06% false-positive cost, reported as evidence rather than as a fix. Findings like this one came out ' +
  'of auditing the project against itself using numbered work orders with binding acceptance criteria, where an ' +
  'item counts as fixed only once its check has been run and the output recorded. Several findings remain open and ' +
  'are listed as open.'
));

body.push(P(
  'Each forecast is accompanied by gradient-times-input feature attributions and the model’s attention over ' +
  'recent windows. Stages produced by a rule rather than the trained classifier are labelled as such. Every alert is ' +
  'written to an append-only SHA-256 hash chain that verifies on read, and reportable incidents are drafted against ' +
  'CERT-In’s six-hour window with a live countdown. Everything runs offline with no cloud calls, input is PCAP ' +
  'or CICFlowMeter CSV, interactive analysis takes 9.9 ms and 5,000 hosts are scored in 60 ms. The Transformer is ' +
  'benchmarked against logistic regression, an LSTM, a Markov chain and a persistence baseline, with the last two ' +
  'named as label oracles.'
));

const doc = new Document({
  creator: 'Team CipherWraiths',
  title: 'AI-Based Network Attack Forecasting Using Explainable World Model Dynamics',
  sections: [{
    properties: { page: { margin: { top: 1080, right: 1080, bottom: 1080, left: 1080 } } },
    children: body,
  }],
});

Packer.toBuffer(doc).then((buf) => {
  fs.writeFileSync(process.argv[2] || 'SIH26153_Idea_Submission_corrected.docx', buf);
  console.log('written');
});
