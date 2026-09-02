"""Command line interface for SWARMS.

    swarms init                 write a starter policy into this directory
    swarms serve                run the gateway and operator console
    swarms policy check         validate and lint a policy
    swarms redteam              run the attack corpus against a policy
    swarms audit                read the decision log
    swarms keygen               mint an API key

argparse rather than click or typer: this is a handful of subcommands with
flags, and the standard library does that without adding a dependency to a
security tool.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys

from swarms import __version__


def _policy(args):
    from swarms.config import Policy
    return Policy.load(args.policy) if args.policy else Policy.discover()


def cmd_init(args) -> int:
    from swarms.config import Policy
    target = os.path.abspath(args.output)
    if os.path.exists(target) and not args.force:
        print(f"{target} already exists (use --force to overwrite)", file=sys.stderr)
        return 1
    source = os.path.join(os.path.dirname(os.path.abspath(__file__)), "default_policy.yaml")
    shutil.copyfile(source, target)
    policy = Policy.load(target)
    print(f"wrote {target}")
    print(f"  {len(policy.actions)} actions, {len(policy.principals)} principals")
    print("\nNext: replace the actions with your own tools, then run:")
    print("  swarms policy check")
    print("  swarms redteam")
    return 0


def cmd_serve(args) -> int:
    import uvicorn
    if args.policy:
        os.environ["SWARMS_POLICY"] = os.path.abspath(args.policy)
    if args.db:
        os.environ["SWARMS_DB"] = args.db
    if args.observe:
        os.environ["SWARMS_ENFORCE"] = "0"
        print("observe-only: decisions are recorded, nothing is blocked")
    uvicorn.run("swarms.server.app:app", host=args.host, port=args.port,
                reload=args.reload, log_level=args.log_level)
    return 0


def cmd_policy_check(args) -> int:
    from swarms.config import PolicyError
    try:
        policy = _policy(args)
    except PolicyError as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 1

    where = f"  ({policy.source_path})" if policy.source_path else ""
    print(f"OK  {policy.name}{where}")
    print(f"    {len(policy.actions)} actions, {len(policy.principals)} principals")
    for name, action in sorted(policy.actions.items()):
        flag = "  [approval]" if action.require_approval else ""
        print(f"      {name:<16} {action.capability:<18} control={list(action.control_args)}{flag}")
    notes = policy.lint()
    if notes:
        print("\n    advisories:")
        for note in notes:
            print(f"      - {note}")
    return 1 if (notes and args.strict) else 0


def cmd_policy_show(args) -> int:
    print(json.dumps(_policy(args).to_dict(), indent=2))
    return 0


def cmd_redteam(args) -> int:
    from swarms.redteam.runner import format_report, run_suite, write_report
    report = run_suite(policy_path=args.policy)
    summary = report["summary"]
    print(format_report(summary))

    web_dir = args.web_dir or None
    write_report(report, args.output, web_dir=web_dir)
    extra = f" and {web_dir}/redteam.json" if web_dir else ""
    print(f"  wrote {args.output}{extra}\n")

    if args.strict and (summary["failures"] or summary["baseline_gaps"]):
        return 1
    return 0


def cmd_audit(args) -> int:
    from swarms.store import AuditStore
    store = AuditStore(args.db)
    if args.stats:
        print(json.dumps(store.stats(args.hours), indent=2))
        return 0
    rows = store.decisions(limit=args.limit, effect=args.effect, action=args.action,
                           principal=args.principal, search=args.search)
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0
    if not rows:
        print("no decisions recorded")
        return 0
    print(f"{'time':<26}{'effect':<10}{'action':<16}{'principal':<18}reason")
    for r in rows:
        principal = (r["principal"] or "")[:17]
        print(f"{r['ts']:<26}{r['effect']:<10}{r['action'][:15]:<16}{principal:<18}{r['reason'][:70]}")
    return 0


def cmd_keygen(args) -> int:
    from swarms.server.auth import generate_key
    key = generate_key()
    print(key)
    print(f"\nUse it:  SWARMS_API_KEYS={key}:{args.name}:{args.role}", file=sys.stderr)
    return 0


def cmd_version(args) -> int:
    print(f"swarms {__version__}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="swarms",
                                     description="Policy enforcement for AI agent tool calls.")
    parser.add_argument("--version", action="version", version=f"swarms {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="write a starter policy file")
    p.add_argument("-o", "--output", default="swarms.yaml")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("serve", help="run the gateway and operator console")
    p.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"))
    p.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8000")))
    p.add_argument("--policy", help="policy file (default: discovered by walking up)")
    p.add_argument("--db", help="audit database path")
    p.add_argument("--observe", action="store_true",
                   help="record decisions without blocking anything")
    p.add_argument("--reload", action="store_true")
    p.add_argument("--log-level", default="info")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("policy", help="inspect a policy")
    psub = p.add_subparsers(dest="policy_command", required=True)
    c = psub.add_parser("check", help="validate and lint")
    c.add_argument("--policy")
    c.add_argument("--strict", action="store_true", help="exit non-zero on advisories too")
    c.set_defaults(func=cmd_policy_check)
    c = psub.add_parser("show", help="print the resolved policy as JSON")
    c.add_argument("--policy")
    c.set_defaults(func=cmd_policy_show)

    p = sub.add_parser("redteam", help="run the attack corpus against a policy")
    p.add_argument("--policy")
    p.add_argument("-o", "--output", default="redteam-report.json")
    p.add_argument("--web-dir", default="",
                   help="also write the console's copy here, e.g. web/data")
    p.add_argument("--strict", action="store_true", help="exit non-zero on any failure")
    p.set_defaults(func=cmd_redteam)

    p = sub.add_parser("audit", help="read the decision log")
    p.add_argument("--db", default=os.environ.get("SWARMS_DB", "swarms.db"))
    p.add_argument("-n", "--limit", type=int, default=50)
    p.add_argument("--effect", choices=["allow", "deny", "require_approval"])
    p.add_argument("--action")
    p.add_argument("--principal")
    p.add_argument("--search")
    p.add_argument("--stats", action="store_true")
    p.add_argument("--hours", type=int, default=24)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_audit)

    p = sub.add_parser("keygen", help="mint an API key")
    p.add_argument("--name", default="default")
    p.add_argument("--role", default="service", choices=["admin", "service", "viewer"])
    p.set_defaults(func=cmd_keygen)

    sub.add_parser("version", help="print the version").set_defaults(func=cmd_version)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
