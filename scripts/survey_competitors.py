"""Re-run the PS 26153 competitor field survey via the GitHub search API.

Same 10 queries as the 2026-09-17 / 09-27 / 09-30 passes, so counts are comparable across
passes. Anything that changes the query set changes the count for reasons that have nothing to
do with the field growing -- the 09-27 pass learned that the hard way (72 -> 123 was mostly a
wider query set, not 51 new competitors).

Requires the `gh` CLI, authenticated.

    python -m scripts.survey_competitors
    python -m scripts.survey_competitors --since 2026-09-30T01:52:00Z
"""
from __future__ import annotations

import argparse
import json
import subprocess
from datetime import datetime, timezone

QUERIES = [
    "SIH26153",
    "PS26153",
    "sih 26153",
    '"network attack forecasting"',
    '"attack forecasting"',
    '"attack stage" prediction network',
    '"world model" cybersecurity',
    '"world model" network traffic',
    "forecasting CICIDS",
    '"attacker progression"',
]

# Excluded as keyword collisions in earlier passes; kept so the count stays comparable.
OFF_TOPIC = {
    "AdityaSinghO/GTD-Dashboard", "AnkushKr836/AI_Military_Intelligence_Dashboard",
    "Nithyasri31/MILITARY-INTELLIGENCE-DASHBOARD", "AnanyaShirshi/Smart-Steering-Wheel",
    "Aditya-xcity/BattleDataExplorer", "venkat15vk/network-attack-forecasting",
    "Mouliprasad2002/cyber-attack-forecasting-arima", "metaordo/StarCore",
    "TraceHanami/AIVA-Ks", "sharmaronit/Defnet",
}
OWN_REPO = "Yashbandiwadekar/network-attack-forecasting"
# SIH 2026 team formation; anything older is a pre-existing project, not a competitor.
WINDOW_START = datetime(2026, 6, 1, tzinfo=timezone.utc)


def search(query: str) -> list[dict]:
    out = subprocess.run(
        ["gh", "api", "-X", "GET", "search/repositories",
         "-f", f"q={query}", "-f", "per_page=100", "--jq",
         ".items[] | {full_name, description, created_at, pushed_at, stargazers_count, size, language}"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",  # repo descriptions carry emoji/non-cp1252 bytes
    )
    if out.returncode != 0:
        print(f"  [!] query failed: {query} -- {out.stderr.strip()[:100]}")
        return []
    return [json.loads(line) for line in out.stdout.splitlines() if line.strip()]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--since", default="2026-09-30T01:52:00Z",
                        help="prior survey timestamp; repos created after this are reported as new")
    args = parser.parse_args()
    since = datetime.fromisoformat(args.since.replace("Z", "+00:00"))

    found: dict[str, dict] = {}
    raw_hits = 0
    for q in QUERIES:
        items = search(q)
        raw_hits += len(items)
        print(f"  {len(items):>4} hits  {q}")
        for it in items:
            found.setdefault(it["full_name"], it)

    field, excluded_old, excluded_offtopic = {}, 0, 0
    for name, it in found.items():
        if name == OWN_REPO:
            continue
        if name in OFF_TOPIC:
            excluded_offtopic += 1
            continue
        if datetime.fromisoformat(it["created_at"].replace("Z", "+00:00")) < WINDOW_START:
            excluded_old += 1
            continue
        field[name] = it

    owners = {n.split("/")[0] for n in field}
    high_conf = [n for n, it in field.items()
                 if any(k in (n + " " + (it.get("description") or "")).lower()
                        for k in ("sih", "26153", "ntro"))]
    new = {n: it for n, it in field.items()
           if datetime.fromisoformat(it["created_at"].replace("Z", "+00:00")) > since}
    pushed = {n: it for n, it in field.items()
              if datetime.fromisoformat(it["pushed_at"].replace("Z", "+00:00")) > since}

    print(f"\nraw query hits (with duplicates): {raw_hits}")
    print(f"unique repositories returned    : {len(found)}")
    print(f"excluded: own repo 1, off-topic {excluded_offtopic}, pre-{WINDOW_START:%Y-%m-%d} {excluded_old}")
    print(f"\nFIELD SIZE                      : {len(field)} repos / {len(owners)} owners")
    print(f"high confidence (SIH/26153/NTRO) : {len(high_conf)}")
    print(f"created since {args.since}   : {len(new)}")
    print(f"pushed  since {args.since}   : {len(pushed)}")

    if new:
        print("\nNEW since the last pass:")
        for n, it in sorted(new.items(), key=lambda kv: kv[1]["created_at"]):
            desc = (it.get("description") or "(no description)")[:96]
            print(f"  {it['created_at'][:10]}  {n}\n      {desc}")

    print("\nMOST RECENTLY PUSHED (top 12):")
    for n, it in sorted(field.items(), key=lambda kv: kv[1]["pushed_at"], reverse=True)[:12]:
        print(f"  {it['pushed_at'][:16].replace('T',' ')}  {it['stargazers_count']:>2}*  "
              f"{it['size']:>7}KB  {n}")


if __name__ == "__main__":
    main()
