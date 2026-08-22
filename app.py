#!/usr/bin/env python3
"""
Security Group Risk Dashboard — local web app
================================================
Serves the dashboard UI and API endpoints that run a live AWS scan on
demand, across one or many AWS accounts. Click "Scan" in the browser —
no manual file upload, no pre-exported JSON.

MULTI-ACCOUNT SETUP
--------------------
Create accounts.json next to this file (see accounts.json.example) to
define the accounts the dashboard can scan — each one either via an
assumed IAM role (recommended for a shared deployment) or a local AWS
profile. See "Scanning multiple AWS accounts" in DEPLOYMENT.md.
Without accounts.json, the dashboard still works exactly as before in
single-account/ad-hoc mode (type a profile/region and scan).

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
    # then open http://localhost:5001

SECURITY NOTE
-------------
Scans run server-side using your normal AWS credential chain (and, for
configured accounts, cross-account role assumption). Your AWS keys never
reach the browser — only the resulting findings JSON does. This app has
no authentication of its own, so don't expose it on the open internet
as-is — see DEPLOYMENT.md for putting it behind a login.
"""

import json
import os
from datetime import datetime, timezone

from flask import Flask, jsonify, request, send_from_directory
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound

from sg_risk_analyzer_live import (
    get_session, get_session_for_account, get_account_context,
    load_accounts_config, run_scan, analyze_all, summarize,
    generate_ai_summary_any, SEVERITY_ORDER,
)
from exemptions import apply_exemption
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ACCOUNTS_CONFIG_PATH = os.environ.get("ACCOUNTS_CONFIG", os.path.join(BASE_DIR, "accounts.json"))
app = Flask(__name__, static_folder=None)


def _load_accounts():
    try:
        return load_accounts_config(ACCOUNTS_CONFIG_PATH)
    except (OSError, json.JSONDecodeError) as e:
        app.logger.warning(f"Could not read accounts config: {e}")
        return []


@app.route("/")
def index():
    return send_from_directory(BASE_DIR, "dashboard.html")


@app.route("/api/accounts")
def api_accounts():
    """Lists the accounts configured in accounts.json (no secrets/ARNs
    exposed to the browser — just what the picker needs)."""
    accounts = _load_accounts()
    return jsonify({
        "accounts": [
            {
                "id": a.get("id"),
                "label": a.get("label", a.get("id")),
                "mode": "role" if a.get("role_arn") else "profile",
                "all_regions": bool(a.get("all_regions", False)),
                "region": a.get("region"),
            }
            for a in accounts if a.get("id")
        ]
    })


def _summary_with_by_account(findings, total_sgs, total_unused, account_meta):
    """Same shape as summarize(), plus a by_account breakdown for the
    multi-account comparison view."""
    summary = summarize(findings, total_sgs, total_unused)
    by_account = {}
    for meta in account_meta:
        label = meta["account_label"]
        acct_findings = [f for f in findings if f.get("account_label") == label]
        counts = {}
        for f in acct_findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        by_account[label] = {
            "account_id": meta["account_id"],
            "total_sgs": meta["total_sgs"],
            "unused_sgs": meta["total_unused"],
            "total_findings": len(acct_findings),
            "by_severity": counts,
            "regions": meta["regions"],
            "skipped_regions": meta["skipped"],
        }
    summary["by_account"] = by_account
    return summary


@app.route("/api/scan")
def api_scan():
    """
    Runs a live scan and returns findings JSON for the dashboard.

    MULTI-ACCOUNT (preferred): pass one or more configured account ids.
      accounts     comma-separated ids from accounts.json, or 'all'

    LEGACY / AD-HOC single account (used when 'accounts' is omitted):
      profile      AWS CLI profile name
      region       single region to scan
      all_regions  'true' to scan every enabled region

    Shared, either mode:
      ai           'true' to include an AI executive summary
      ai_provider  'anthropic' (default) or 'ollama' (fully local)
      model        model id — Claude model name, or Ollama model tag
      ollama_host  Ollama server URL (default http://localhost:11434)
    """
    use_ai = request.args.get("ai", "false").lower() == "true"
    ai_provider = request.args.get("ai_provider", "anthropic")
    model = request.args.get("model") or None
    ollama_host = request.args.get("ollama_host") or os.environ.get("OLLAMA_HOST", "http://localhost:11434")
    accounts_param = request.args.get("accounts")

    all_configured = _load_accounts()

    # ---------------- Multi-account mode ----------------
    if accounts_param:
        requested_ids = None if accounts_param == "all" else set(accounts_param.split(","))
        targets = [a for a in all_configured if requested_ids is None or a.get("id") in requested_ids]
        if not targets:
            return jsonify({"error": "No matching accounts found in accounts.json."}), 400

        try:
            base_session = get_session(request.args.get("profile") or None, request.args.get("region") or None)
        except ProfileNotFound as e:
            return jsonify({"error": f"Server credentials not found: {e}"}), 401

        all_findings, account_meta, account_errors = [], [], []
        for acct in targets:
            label = acct.get("label", acct.get("id"))
            try:
                session = get_session_for_account(acct, base_session=base_session)
                real_account_id, _ = get_account_context(session)
            except RuntimeError as e:
                account_errors.append({"account": label, "reason": str(e)})
                continue
            acct_all_regions = acct.get("all_regions", False)
            acct_region = acct.get("region")
            try:
                findings, sgs_n, unused_n, scanned, skipped = run_scan(session, acct_all_regions, acct_region)
            except ClientError as e:
                account_errors.append({"account": label, "reason": str(e)})
                continue
            for f in findings:
                f["account_id"] = real_account_id
                f["account_label"] = label
                apply_exemption(f)
            all_findings.extend(findings)
            account_meta.append({
                "account_label": label, "account_id": real_account_id,
                "total_sgs": sgs_n, "total_unused": unused_n,
                "regions": scanned, "skipped": skipped,
            })

        if not account_meta:
            return jsonify({"error": "No accounts could be scanned.", "skipped_accounts": account_errors}), 500

        all_findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["account_label"], f["region"], f["sg_id"]))
        total_sgs = sum(m["total_sgs"] for m in account_meta)
        total_unused = sum(m["total_unused"] for m in account_meta)
        summary = _summary_with_by_account(all_findings, total_sgs, total_unused, account_meta)
        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        ai_summary = None
        if use_ai:
            combined_label = f"{len(account_meta)} account(s): " + ", ".join(m["account_label"] for m in account_meta)
            ai_summary = generate_ai_summary_any(all_findings, summary, combined_label,
                                                  provider=ai_provider, model=model,
                                                  ollama_host=ollama_host)

        regions_union = sorted({r for m in account_meta for r in m["regions"]})
        return jsonify({
            "generated_at": generated_at,
            "multi_account": True,
            "account_id": f"{len(account_meta)} account(s)",
            "accounts": [{"label": m["account_label"], "account_id": m["account_id"]} for m in account_meta],
            "skipped_accounts": account_errors,
            "regions": regions_union,
            "summary": summary,
            "ai_summary": ai_summary,
            "findings": all_findings,
        })

    # ---------------- Legacy / ad-hoc single-account mode ----------------
    profile = request.args.get("profile") or None
    region = request.args.get("region") or None
    all_regions = request.args.get("all_regions", "false").lower() == "true"

    try:
        session = get_session(profile, region)
        account_id, _ = get_account_context(session)
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 401
    except ProfileNotFound as e:
        return jsonify({"error": f"Profile not found: {e}"}), 401

    try:
        all_findings, total_sgs, total_unused, scanned_regions, skipped = run_scan(session, all_regions, region)
    except ClientError as e:
        return jsonify({"error": f"Could not scan account: {e}"}), 500

    if not scanned_regions:
        return jsonify({"error": "No regions could be scanned. Check permissions and region name.",
                         "skipped": skipped}), 500

    for f in all_findings:
        f["account_id"] = account_id
        f["account_label"] = "Ad-hoc scan"
        apply_exemption(f)

    summary = summarize(all_findings, total_sgs, total_unused)
    summary["by_account"] = {
        "Ad-hoc scan": {
            "account_id": account_id, "total_sgs": total_sgs, "unused_sgs": total_unused,
            "total_findings": len(all_findings), "by_severity": summary["by_severity"],
            "regions": scanned_regions, "skipped_regions": skipped,
        }
    }
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    ai_summary = None
    if use_ai:
        ai_summary = generate_ai_summary_any(all_findings, summary, account_id,
                                              provider=ai_provider, model=model,
                                              ollama_host=ollama_host)

    return jsonify({
        "generated_at": generated_at,
        "multi_account": False,
        "account_id": account_id,
        "accounts": [{"label": "Ad-hoc scan", "account_id": account_id}],
        "skipped_accounts": [],
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
