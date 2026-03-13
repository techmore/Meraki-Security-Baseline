#!/usr/bin/env python3
import json
import os
import sys
import urllib.request
import urllib.error

from meraki_env import load_env

API_BASE = "https://api.meraki.com/api/v1"


def api_get(path: str, api_key: str):
    url = f"{API_BASE}{path}"
    req = urllib.request.Request(url, headers={
        "X-Cisco-Meraki-API-Key": api_key,
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req) as resp:
            data = resp.read().decode("utf-8")
            return json.loads(data)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8") if e.fp else ""
        raise RuntimeError(f"HTTP {e.code} for {url}: {body}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"Network error for {url}: {e}")


def main():
    load_env()
    api_key = os.getenv("MERAKI_API_KEY")
    if not api_key:
        print("Missing MERAKI_API_KEY env var.", file=sys.stderr)
        print("Example: export MERAKI_API_KEY=your_key_here", file=sys.stderr)
        sys.exit(1)

    orgs = api_get("/organizations", api_key)
    print(json.dumps(orgs, indent=2))


if __name__ == "__main__":
    main()
