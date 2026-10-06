#!/usr/bin/env python3
"""Markdown comparison tables for a live-matrix run.

Usage: live-matrix-summary.py DIR ID=LABEL...
Reads DIR/<id>/status and DIR/<id>/result.json as written by
`scripts/live-matrix.sh run`; envs with no directory are omitted.
"""
import json
import os
import sys

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEV_BADGE = {
    "critical": "🚨 Critical",
    "high": "⚠️ High",
    "medium": "🟡 Med",
    "low": "🔵 Low",
    "info": "ℹ️ Info",
}


def main() -> None:
    root, pairs = sys.argv[1], sys.argv[2:]
    envs = [tuple(p.split("=", 1)) for p in pairs]

    env_results: dict[str, list] = {}
    rows = []
    for env_id, label in envs:
        d = os.path.join(root, env_id)
        if not os.path.isdir(d):
            continue
        status_path = os.path.join(d, "status")
        status = open(status_path).read().strip() if os.path.exists(status_path) else "missing status"
        if status != "ok":
            rows.append((label, f"*{status}*", "-", "-", "-"))
            continue
        try:
            data = json.load(open(os.path.join(d, "result.json")))
            verdict = data.get("verdict") or {}
            runtime = verdict.get("runtime", "unknown")
            qual = verdict.get("variant") or verdict.get("confidence")
            verdict_str = f"`{runtime}` ({qual})" if qual else f"`{runtime}`"

            scan = data.get("scan", {})
            uid, user = scan.get("uid", "?"), scan.get("user")
            id_str = f"{uid} ({user})" if user else str(uid)

            findings = data.get("findings", [])
            rule_ids = [f.get("rule", "") for f in findings]
            env_results[env_id] = findings
            rows.append((label, verdict_str, id_str, str(len(findings)), ", ".join(rule_ids) or "*None*"))
        except Exception as e:  # report the broken env, keep the table
            rows.append((label, f"Error: {e}", "-", "-", "-"))

    print("## Live Environment Matrix Comparison\n")
    print("### 1. Environment Runtime Verdicts\n")
    print("| Environment | Detected Runtime | User / UID | Findings Count | Triggered Findings |")
    print("| :--- | :--- | :--- | :--- | :--- |")
    for r in rows:
        print("| " + " | ".join(r) + " |")

    all_findings: dict[str, dict] = {}
    for flist in env_results.values():
        for f in flist:
            rid = f.get("rule", "")
            if rid and rid not in all_findings:
                all_findings[rid] = {
                    "rule": rid,
                    "severity": f.get("severity", "info").lower(),
                    "summary": f.get("summary", ""),
                }
    sorted_rules = sorted(all_findings.values(), key=lambda x: (SEV_ORDER.get(x["severity"], 99), x["rule"]))

    cols_envs = [(i, label) for i, label in envs if i in env_results]
    print("\n### 2. Finding-to-Runtime Security Posture Matrix\n")
    headers = ["Finding (Rule ID & Summary)", "Severity"] + [label for _, label in cols_envs]
    print("| " + " | ".join(headers) + " |")
    print("| :--- | :--- | " + " | ".join([":---:"] * len(cols_envs)) + " |")
    for r in sorted_rules:
        rid = r["rule"]
        cols = []
        for env_id, _ in cols_envs:
            hits = [f for f in env_results[env_id] if f.get("rule") == rid]
            cols.append(SEV_BADGE.get(hits[0].get("severity", "").lower(), "✅") if hits else "·")
        badge = SEV_BADGE.get(r["severity"], r["severity"])
        print(f"| `{rid}` {r['summary']} | {badge} | " + " | ".join(cols) + " |")


if __name__ == "__main__":
    main()
