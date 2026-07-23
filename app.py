#!/usr/bin/env python3
"""
Security Group Risk Dashboard — local web app
================================================
Serves the dashboard UI and an API endpoint that runs a live AWS scan
on demand. Click "Generate report" in the browser — no manual file
upload, no pre-exported JSON.

SETUP
-----
    pip install flask boto3 requests --break-system-packages
    export ANTHROPIC_API_KEY=sk-ant-...   # optional, enables the AI summary

    # AWS credentials, same as the CLI tool:
    aws configure --profile myprofile
    # or env vars, or an attached IAM role if running on EC2/CloudShell

RUN
---
    python3 app.py
    # then open http://localhost:5001 and click "Generate report"

SECURITY NOTE
-------------
The scan runs server-side using your normal AWS credential chain.
Your AWS keys never reach the browser — only the resulting findings
JSON does. This app is intended to run on your own machine (or an
internal host you control); it has no authentication of its own, so
don't expose it on the open internet as-is.
"""

import os
from datetime import datetime, timezone

from flask import Flask, jsonify, request, send_from_directory
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound

from sg_risk_analyzer_live import (
    get_session, get_account_context, list_target_regions,
    fetch_security_groups, fetch_network_interfaces, build_sg_usage_map,
    analyze_all, summarize, generate_ai_summary_any, SEVERITY_ORDER,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, static_folder=None)


@app.route("/")
def index():
    return send_from_directory(BASE_DIR, "dashboard.html")


@app.route("/sample_findings.json")
def sample():
    return send_from_directory(BASE_DIR, "sample_findings.json")


@app.route("/api/scan")
def api_scan():
    """
    Runs a live scan and returns the same JSON shape the CLI's --json
    flag produces. Query params (all optional):
      profile      AWS CLI profile name
      region       single region to scan
      all_regions  'true' to scan every enabled region
      ai           'true' to include an AI executive summary
      ai_provider  'anthropic' (default) or 'ollama' (fully local)
      model        model id — Claude model name, or Ollama model tag
      ollama_host  Ollama server URL (default http://localhost:11434)
    """
    profile = request.args.get("profile") or None
    region = request.args.get("region") or None
    all_regions = request.args.get("all_regions", "false").lower() == "true"
    use_ai = request.args.get("ai", "false").lower() == "true"
    ai_provider = request.args.get("ai_provider", "anthropic")
    model = request.args.get("model") or None
    ollama_host = request.args.get("ollama_host") or os.environ.get("OLLAMA_HOST", "http://localhost:11434")

    try:
        session = get_session(profile, region)
        account_id, _ = get_account_context(session)
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 401
    except ProfileNotFound as e:
        return jsonify({"error": f"Profile not found: {e}"}), 401

    try:
        regions = list_target_regions(session, all_regions, region)
    except ClientError as e:
        return jsonify({"error": f"Could not list regions: {e}"}), 500

    all_findings, total_sgs, total_unused, scanned_regions, skipped = [], 0, 0, [], []
    for r in regions:
        try:
            sgs = fetch_security_groups(session, r)
            enis = fetch_network_interfaces(session, r)
        except ClientError as e:
            skipped.append({"region": r, "reason": str(e)})
            continue
        usage_map = build_sg_usage_map(enis)
        findings = analyze_all(sgs, usage_map, r)
        all_findings.extend(findings)
        total_sgs += len(sgs)
        total_unused += sum(
            1 for sg in sgs
            if sg.get("GroupName") != "default" and not usage_map.get(sg.get("GroupId"), [])
        )
        scanned_regions.append(r)

    if not scanned_regions:
        return jsonify({"error": "No regions could be scanned. Check permissions and region name.",
                         "skipped": skipped}), 500

    all_findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["region"], f["sg_id"]))
    summary = summarize(all_findings, total_sgs, total_unused)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    ai_summary = None
    if use_ai:
        ai_summary = generate_ai_summary_any(all_findings, summary, account_id,
                                              provider=ai_provider, model=model,
                                              ollama_host=ollama_host)

    return jsonify({
        "generated_at": generated_at,
        "account_id": account_id,
        "regions": scanned_regions,
        "skipped_regions": skipped,
        "summary": summary,
        "ai_summary": ai_summary,
        "findings": all_findings,
    })


@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    host = os.environ.get("HOST", "127.0.0.1")  # set HOST=0.0.0.0 for shared/containerized deployment
    print(f"Security Group Risk Dashboard running at http://{host}:{port}")
    print("Press Ctrl+C to stop.")
    print("NOTE: for shared/team use, run this behind gunicorn + a reverse proxy — see DEPLOYMENT.md")
    app.run(host=host, port=port, debug=False)
