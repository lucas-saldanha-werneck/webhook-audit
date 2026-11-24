import argparse
import json
import sys

from .audit import audit, load_events, render_markdown


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="webhook-audit", description=__doc__)
    p.add_argument("log", help="JSON Lines file of webhook deliveries")
    p.add_argument("--secret", help="shared secret to verify signatures")
    p.add_argument("--json", action="store_true", help="print JSON instead of Markdown")
    a = p.parse_args(argv)
    try:
        report = audit(load_events(a.log), a.secret)
    except (OSError, ValueError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2) if a.json else render_markdown(report), end="")
    return 1 if report["findings"] else 0


if __name__ == "__main__":
    sys.exit(main())
