#!/usr/bin/env python3
import os
from datetime import datetime

BASE_DIR = (
    "/Users/seandolbec/Projects/Meraki-2026_planning/meraki_backup_20260311_134144"
)


def main() -> int:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    out_path = os.path.join(BASE_DIR, "master_recommendations.md")
    with open(out_path, "w", encoding="utf-8") as out:
        out.write(f"# Meraki Master Recommendations\n\n")
        out.write(f"Generated: {ts}\n\n")
        for name in sorted(os.listdir(BASE_DIR)):
            if not name.startswith("org_"):
                continue
            rec_path = os.path.join(BASE_DIR, name, "recommendations.md")
            if not os.path.exists(rec_path):
                continue
            out.write(f"---\n\n")
            with open(rec_path, "r", encoding="utf-8") as f:
                out.write(f.read().rstrip())
                out.write("\n\n")
    print(f"Master recommendations written to: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
