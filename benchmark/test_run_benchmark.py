"""Minimal smoke test, no real Core/swarm needed: fakes run_swarm() and
checks that main() writes the right files with the right shapes. Run with:
    python -m benchmark.test_run_benchmark
"""
import json
import os
import shutil
import tempfile

from benchmark.run_benchmark import main


def fake_run_swarm(attack, shield_enabled, run_id):
    events_path = os.path.join(tempfile.gettempdir(), f"{run_id}_events.jsonl")
    event = {
        "event_id": "evt_0001", "timestamp": "2026-01-01T00:00:00Z", "run_id": run_id,
        "type": "ACTION_ALLOWED" if not shield_enabled else "ACTION_BLOCKED",
        "agent": "agent3_emailer",
        "data": {"action": "send_email", "reason": "test"},
    }
    with open(events_path, "w", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")
    return {
        "run_id": run_id,
        "malicious_action_executed": not shield_enabled,
        "events_path": events_path,
    }


def demo():
    tmp = tempfile.mkdtemp()
    try:
        attacks_dir = os.path.join(tmp, "attacks")
        web_data_dir = os.path.join(tmp, "web_data")
        results_csv = os.path.join(tmp, "results.csv")
        os.makedirs(attacks_dir)

        with open(os.path.join(attacks_dir, "attack_001.json"), "w", encoding="utf-8") as f:
            json.dump({"attack_id": "attack_001", "name": "fake", "category": "test"}, f)

        summary = main(attacks_dir=attacks_dir, web_data_dir=web_data_dir, results_csv=results_csv, run_swarm=fake_run_swarm)

        assert summary["total_attacks"] == 1
        assert summary["shield_off_success_rate"] == 1.0, "fake run_swarm always succeeds when shield is off"
        assert summary["shield_on_success_rate"] == 0.0, "fake run_swarm always blocks when shield is on"
        assert os.path.exists(results_csv)
        assert os.path.exists(os.path.join(web_data_dir, "manifest.json"))
        assert os.path.exists(os.path.join(web_data_dir, "benchmark_summary.json"))
        assert os.path.exists(os.path.join(web_data_dir, "attack_001_off.json"))
        assert os.path.exists(os.path.join(web_data_dir, "attack_001_on.json"))

        with open(os.path.join(web_data_dir, "attack_001_off.json"), encoding="utf-8") as f:
            off_events = json.load(f)
        assert off_events[0]["type"] == "ACTION_ALLOWED"

        print("benchmark self-check passed")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    demo()
