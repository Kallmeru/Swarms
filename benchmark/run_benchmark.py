"""Runs every swarm/attacks/attack_*.json through the swarm twice, once with
the shield disabled (baseline) and once enabled, then writes:
  - benchmark/results.csv               (per-attack, per-mode outcome)
  - web/data/manifest.json              (attack list for the frontend dropdown)
  - web/data/benchmark_summary.json     (aggregate success rates, for the bar chart)
  - web/data/<attack_id>_off.json       (event log, off mode, as a JSON array)
  - web/data/<attack_id>_on.json        (event log, on mode, as a JSON array)

Depends on swarm.run_swarm.run_swarm(attack, shield_enabled, run_id) existing
and returning {"run_id", "malicious_action_executed", "events_path"}, per the
integration contract in docs/swarms-integration-schema.md. Nothing here talks
to core/ or swarm/ directly beyond that one function call, on purpose, so
either side can change its internals without breaking this script.
"""
import csv
import glob
import json
import os

ATTACKS_DIR = "swarm/attacks"
WEB_DATA_DIR = "web/data"
RESULTS_CSV = "benchmark/results.csv"


def _default_run_swarm():
    from swarm.run_swarm import run_swarm
    return run_swarm


def load_attacks(attacks_dir: str = ATTACKS_DIR):
    paths = sorted(glob.glob(os.path.join(attacks_dir, "attack_*.json")))
    if not paths:
        raise SystemExit(
            f"No attack files found in {attacks_dir}/. "
            "Nothing to benchmark yet, swarm/attacks/ needs at least one attack_*.json."
        )
    attacks = []
    for path in paths:
        with open(path, encoding="utf-8") as f:
            attacks.append(json.load(f))
    return attacks


def events_to_json_array(events_path: str) -> list[dict]:
    if not os.path.exists(events_path):
        return []
    with open(events_path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def export_for_web(attack_id: str, mode: str, events: list[dict], web_data_dir: str = WEB_DATA_DIR):
    os.makedirs(web_data_dir, exist_ok=True)
    out_path = os.path.join(web_data_dir, f"{attack_id}_{mode}.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(events, f, indent=2)


def main(attacks_dir=ATTACKS_DIR, web_data_dir=WEB_DATA_DIR, results_csv=RESULTS_CSV, run_swarm=None):
    run_swarm = run_swarm or _default_run_swarm()
    attacks = load_attacks(attacks_dir)
    rows = []
    manifest = []
    off_success, on_success = 0, 0

    for attack in attacks:
        attack_id = attack["attack_id"]
        for mode, shield_on in [("off", False), ("on", True)]:
            run_id = f"{attack_id}_{mode}"
            result = run_swarm(attack, shield_enabled=shield_on, run_id=run_id)
            events = events_to_json_array(result["events_path"])
            export_for_web(attack_id, mode, events, web_data_dir)

            executed = result["malicious_action_executed"]
            if mode == "off" and executed:
                off_success += 1
            if mode == "on" and executed:
                on_success += 1
            rows.append({
                "attack_id": attack_id,
                "category": attack.get("category", ""),
                "mode": mode,
                "malicious_action_executed": executed,
            })
        manifest.append({
            "attack_id": attack_id,
            "name": attack.get("name", attack_id),
            "category": attack.get("category", ""),
        })

    os.makedirs(os.path.dirname(results_csv) or ".", exist_ok=True)
    with open(results_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["attack_id", "category", "mode", "malicious_action_executed"])
        writer.writeheader()
        writer.writerows(rows)

    total = len(attacks)
    summary = {
        "total_attacks": total,
        "shield_off_success_rate": round(off_success / total, 3),
        "shield_on_success_rate": round(on_success / total, 3),
    }
    os.makedirs(web_data_dir, exist_ok=True)
    with open(os.path.join(web_data_dir, "benchmark_summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    with open(os.path.join(web_data_dir, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print(f"Shield OFF: {off_success}/{total} attacks succeeded ({summary['shield_off_success_rate'] * 100:.0f}%)")
    print(f"Shield ON:  {on_success}/{total} attacks succeeded ({summary['shield_on_success_rate'] * 100:.0f}%)")
    print(f"Wrote {results_csv} and {web_data_dir}/*.json")
    return summary


if __name__ == "__main__":
    main()
