#!/usr/bin/env python3
"""
AWS Security Group Risk Analyzer — Live / On-Demand
=====================================================

Run this ANY time you want a fresh security review of your AWS account's
Security Groups. It talks to AWS directly (via boto3 + your existing AWS
credentials) — no manual export step required.

WHAT IT CHECKS
--------------
  - Overly permissive ingress/egress rules (0.0.0.0/0, ::/0)
  - Exposed sensitive/management ports (SSH, RDP, databases, Redis, etc.)
  - "Any protocol / any port" rules
  - Unused security groups (not attached to any network interface)
  - Unrestricted egress
  - Active use of the default security group
  - Missing tags / naming hygiene issues

OPTIONAL AI LAYER
------------------
Pass --ai to have Claude read the findings and produce a prioritized,
plain-English executive summary and remediation plan. Requires the
ANTHROPIC_API_KEY environment variable to be set. Without --ai, you still
get the full deterministic findings report — the AI layer only adds the
narrative/prioritization on top.

SETUP
-----
    pip install boto3 --break-system-packages
    # optional, only needed for --ai:
    pip install requests --break-system-packages

    # Make sure AWS credentials are available, e.g.:
    aws configure --profile myprofile
    # or export AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN
    # or run from an EC2 instance / Cloud9 / CloudShell with an attached role

USAGE
-----
    # Scan your default region/profile
    python3 sg_risk_analyzer_live.py

    # Scan a specific profile and region
    python3 sg_risk_analyzer_live.py --profile prod --region us-east-1

    # Scan every enabled region in the account
    python3 sg_risk_analyzer_live.py --all-regions

    # Add the AI-generated executive summary (needs ANTHROPIC_API_KEY)
    python3 sg_risk_analyzer_live.py --all-regions --ai

    # HTML report + CSV of raw findings
    python3 sg_risk_analyzer_live.py --format html --output report.html --csv findings.csv

PERMISSIONS NEEDED
-------------------
Read-only. Attach a policy allowing at minimum:
    ec2:DescribeSecurityGroups
    ec2:DescribeNetworkInterfaces
    ec2:DescribeRegions
    sts:GetCallerIdentity
This script makes NO write/delete calls to your account.
"""

import argparse
import csv
import ipaddress
import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound
except ImportError:
    print("ERROR: boto3 is required. Install it with:\n"
          "  pip install boto3 --break-system-packages", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Reference data: ports/protocols worth flagging, and why
# ---------------------------------------------------------------------------

SENSITIVE_PORTS = {
    22: ("SSH", "Remote administrative shell access"),
    23: ("Telnet", "Unencrypted remote shell — should never be exposed"),
    3389: ("RDP", "Windows remote desktop"),
    3306: ("MySQL/MariaDB", "Database engine port"),
    5432: ("PostgreSQL", "Database engine port"),
    1433: ("MS SQL Server", "Database engine port"),
    1521: ("Oracle DB", "Database engine port"),
    27017: ("MongoDB", "Database engine port"),
    6379: ("Redis", "In-memory data store, often unauthenticated by default"),
    9200: ("Elasticsearch", "Search/index engine, historically a common breach vector"),
    5601: ("Kibana", "Elasticsearch dashboard/UI"),
    9092: ("Kafka", "Message broker"),
    2181: ("Zookeeper", "Cluster coordination service"),
    11211: ("Memcached", "Cache store, frequently abused for DDoS amplification"),
    445: ("SMB", "Windows file sharing, common ransomware vector"),
    135: ("MSRPC", "Windows RPC endpoint mapper"),
    5900: ("VNC", "Remote desktop/screen sharing"),
    21: ("FTP", "Unencrypted file transfer"),
    25: ("SMTP", "Mail relay — open exposure enables spam relay abuse"),
    9300: ("Elasticsearch transport", "Cluster-internal transport port"),
    8080: ("HTTP-alt", "Common alt web/admin port, often unauthenticated apps"),
    8443: ("HTTPS-alt", "Common alt web/admin port"),
    27018: ("MongoDB shard", "Database engine port"),
    5000: ("Docker registry / dev servers", "Frequently left unauthenticated"),
    9000: ("Various admin UIs (Portainer, SonarQube, etc.)", "Often unauthenticated by default"),
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
CRITICAL_PORTS = {22, 3389, 3306, 5432, 1433, 27017, 6379, 445, 23, 21}


# ---------------------------------------------------------------------------
# AWS data collection (live)
# ---------------------------------------------------------------------------

def get_session(profile, region):
    try:
        if profile:
            return boto3.Session(profile_name=profile, region_name=region)
        return boto3.Session(region_name=region)
    except ProfileNotFound as e:
        raise RuntimeError(str(e))


def get_account_context(session):
    try:
        sts = session.client("sts")
        ident = sts.get_caller_identity()
        return ident.get("Account", "unknown"), ident.get("Arn", "unknown")
    except (ClientError, NoCredentialsError) as e:
        raise RuntimeError(
            f"Could not authenticate to AWS: {e}. "
            "Check your credentials (aws configure, env vars, or instance role)."
        )


def list_target_regions(session, all_regions, single_region):
    if not all_regions:
        return [single_region or session.region_name or "us-east-1"]
    ec2 = session.client("ec2", region_name="us-east-1")
    resp = ec2.describe_regions(AllRegions=False)  # only enabled regions
    return sorted(r["RegionName"] for r in resp["Regions"])


def fetch_security_groups(session, region):
    ec2 = session.client("ec2", region_name=region)
    sgs = []
    paginator = ec2.get_paginator("describe_security_groups")
    for page in paginator.paginate():
        sgs.extend(page["SecurityGroups"])
    return sgs


def fetch_network_interfaces(session, region):
    ec2 = session.client("ec2", region_name=region)
    enis = []
    paginator = ec2.get_paginator("describe_network_interfaces")
    for page in paginator.paginate():
        enis.extend(page["NetworkInterfaces"])
    return enis


def build_sg_usage_map(enis):
    usage = defaultdict(list)
    for eni in enis or []:
        eni_id = eni.get("NetworkInterfaceId", "unknown-eni")
        desc = eni.get("Description", "")
        attachment = eni.get("Attachment", {}) or {}
        instance_id = attachment.get("InstanceId")
        label = eni_id + (f" (instance {instance_id})" if instance_id else "")
        if desc:
            label += f" — {desc}"
        for grp in eni.get("Groups", []):
            sg_id = grp.get("GroupId")
            if sg_id:
                usage[sg_id].append(label)
    return usage


# ---------------------------------------------------------------------------
# Rule analysis helpers (deterministic engine)
# ---------------------------------------------------------------------------

def is_open_to_world(cidr):
    return cidr in ("0.0.0.0/0", "::/0")


def port_range_str(rule):
    from_p = rule.get("FromPort")
    to_p = rule.get("ToPort")
    proto = rule.get("IpProtocol", "-1")
    if proto == "-1":
        return "ALL PROTOCOLS / ALL PORTS"
    if from_p is None and to_p is None:
        return f"{proto.upper()} (all ports)"
    if from_p == to_p:
        return f"{proto.upper()}/{from_p}"
    return f"{proto.upper()}/{from_p}-{to_p}"


def covers_port(rule, port):
    proto = rule.get("IpProtocol", "-1")
    if proto == "-1":
        return True
    from_p, to_p = rule.get("FromPort"), rule.get("ToPort")
    if from_p is None or to_p is None:
        return True
    return from_p <= port <= to_p


def get_open_cidrs(rule):
    open_cidrs = []
    for r in rule.get("IpRanges", []):
        cidr = r.get("CidrIp")
        if cidr and is_open_to_world(cidr):
            open_cidrs.append(cidr)
    for r in rule.get("Ipv6Ranges", []):
        cidr = r.get("CidrIpv6")
        if cidr and is_open_to_world(cidr):
            open_cidrs.append(cidr)
    return open_cidrs


def analyze_security_group(sg, usage_map, region):
    findings = []
    sg_id = sg.get("GroupId", "unknown")
    sg_name = sg.get("GroupName", "unnamed")
    vpc_id = sg.get("VpcId", "unknown-vpc")
    tags = {t.get("Key"): t.get("Value") for t in sg.get("Tags", []) or []}

    def add(severity, category, title, detail, remediation):
        findings.append({
            "region": region, "sg_id": sg_id, "sg_name": sg_name, "vpc_id": vpc_id,
            "severity": severity, "category": category, "title": title,
            "detail": detail, "remediation": remediation,
        })

    for rule in sg.get("IpPermissions", []):
        open_cidrs = get_open_cidrs(rule)
        if not open_cidrs:
            continue
        proto = rule.get("IpProtocol", "-1")
        from_p, to_p = rule.get("FromPort"), rule.get("ToPort")
        is_all_ports = proto == "-1" or (from_p in (None, 0) and to_p in (None, 65535))

        if is_all_ports:
            add("CRITICAL", "Overly permissive ingress", "All ports open to the internet",
                f"Rule allows ALL protocols/ports from {', '.join(open_cidrs)}.",
                "Restrict to only the specific ports and protocols required. "
                "Never allow all-ports access from 0.0.0.0/0 or ::/0.")
            continue

        flagged_any = False
        for port, (svc_name, why) in SENSITIVE_PORTS.items():
            if covers_port(rule, port):
                flagged_any = True
                severity = "CRITICAL" if port in CRITICAL_PORTS else "HIGH"
                add(severity, "Exposed sensitive port", f"{svc_name} (port {port}) open to the internet",
                    f"Rule '{port_range_str(rule)}' permits access from {', '.join(open_cidrs)}. {why}.",
                    f"Restrict source to specific IP ranges (e.g. office/VPN CIDR) or remove public access. "
                    f"Prefer a bastion host, AWS SSM Session Manager, or a VPN instead of exposing {svc_name} directly.")

        if not flagged_any:
            span = set(range(from_p or 0, (to_p or 0) + 1))
            if span & {80, 443} and len(span) <= 2:
                add("LOW", "Internet-facing web port", f"Web port open to the internet ({port_range_str(rule)})",
                    f"Rule permits {port_range_str(rule)} from {', '.join(open_cidrs)}. "
                    "Common/expected for public web servers or load balancers — confirm this SG fronts a public resource.",
                    "If attached to internal resources, restrict the source. If public-facing, ensure a WAF and rate limiting are in place.")
            else:
                add("MEDIUM", "Overly permissive ingress", f"Port range open to the internet ({port_range_str(rule)})",
                    f"Rule permits {port_range_str(rule)} from {', '.join(open_cidrs)}.",
                    "Scope the source CIDR down to only the networks that need access.")

    for rule in sg.get("IpPermissionsEgress", []):
        proto = rule.get("IpProtocol", "-1")
        from_p, to_p = rule.get("FromPort"), rule.get("ToPort")
        is_all_ports = proto == "-1" or (from_p in (None, 0) and to_p in (None, 65535))
        if is_all_ports and get_open_cidrs(rule):
            add("LOW", "Unrestricted egress", "Unrestricted outbound access (all ports/protocols to 0.0.0.0/0)",
                "This is the AWS default egress rule. A compromised instance in this SG can freely "
                "exfiltrate data or reach any host.",
                "Consider scoping egress to required destinations/ports for sensitive workloads.")

    attachments = usage_map.get(sg_id, [])
    if not attachments and sg_name != "default":
        add("MEDIUM", "Hygiene", "Security group appears unused",
            "No network interfaces (ENIs) reference this security group.",
            "Verify, then remove if genuinely unused to reduce attack surface and configuration drift.")

    if not tags:
        add("LOW", "Hygiene", "No tags applied",
            "This security group has no tags, making ownership, environment, and purpose unclear.",
            "Apply standard tags (Owner, Environment, Application) per your tagging policy.")

    if sg_name == "default" and attachments:
        add("MEDIUM", "Best practice", "Default security group is actively in use",
            f"The default SG in VPC {vpc_id} is attached to {len(attachments)} interface(s).",
            "Create purpose-specific security groups and migrate resources off the default SG.")

    return findings


def analyze_all(sgs, usage_map, region):
    all_findings = []
    for sg in sgs:
        all_findings.extend(analyze_security_group(sg, usage_map, region))
    all_findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["region"], f["sg_id"]))
    return all_findings


def summarize(findings, total_sgs, total_unused):
    counts = defaultdict(int)
    for f in findings:
        counts[f["severity"]] += 1
    return {"total_sgs": total_sgs, "total_findings": len(findings),
            "by_severity": dict(counts), "unused_sgs": total_unused}


# ---------------------------------------------------------------------------
# Optional AI narrative layer — Claude (cloud) or Ollama (fully local)
# ---------------------------------------------------------------------------

def _build_ai_prompt(findings, summary, account_id):
    top_findings = [f for f in findings if f["severity"] in ("CRITICAL", "HIGH")][:40]
    payload_findings = [
        {k: v for k, v in f.items() if k in
         ("region", "sg_id", "sg_name", "severity", "category", "title", "detail")}
        for f in top_findings
    ]
    return f"""You are a cloud security analyst. Below is a JSON list of AWS Security Group
risk findings (Critical/High severity only, account {account_id}), plus overall counts.

Findings JSON:
{json.dumps(payload_findings, indent=2)}

Overall counts by severity: {json.dumps(summary['by_severity'])}
Total security groups scanned: {summary['total_sgs']}

Write a concise executive summary (max ~200 words) for a security/engineering leadership
audience, covering:
1. Overall risk posture in one or two sentences.
2. The 3-5 most urgent remediation actions, ranked, with a one-line reason each.
3. Any pattern across findings worth calling out (e.g. a recurring team/VPC/naming pattern).

Plain text only, no markdown headers, no preamble."""


def generate_ai_summary(findings, summary, account_id, model="claude-sonnet-5"):
    """Backward-compatible entry point — Anthropic Claude API."""
    return generate_ai_summary_anthropic(findings, summary, account_id, model)


def generate_ai_summary_anthropic(findings, summary, account_id, model="claude-sonnet-5"):
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return ("_AI summary skipped: set the ANTHROPIC_API_KEY environment variable "
                "to enable this section, or switch to the Ollama provider for a local model._")
    try:
        import requests
    except ImportError:
        return "_AI summary skipped: install `requests` (`pip install requests --break-system-packages`)._"

    prompt = _build_ai_prompt(findings, summary, account_id)
    try:
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": model,
                "max_tokens": 700,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=60,
        )
        resp.raise_for_status()
        data = resp.json()
        text_blocks = [b["text"] for b in data.get("content", []) if b.get("type") == "text"]
        return "\n".join(text_blocks) if text_blocks else "_AI summary returned no content._"
    except Exception as e:
        return f"_AI summary failed: {e}_"


def generate_ai_summary_ollama(findings, summary, account_id, model="llama3.1", host="http://localhost:11434"):
    """
    Fully local AI summary via Ollama (https://ollama.com). No API key, no data
    leaves the machine. Requires Ollama to be running (`ollama serve`, which
    `ollama run <model>` starts automatically) and the model to be pulled:
        ollama pull llama3.1
    """
    try:
        import requests
    except ImportError:
        return "_AI summary skipped: install `requests` (`pip install requests --break-system-packages`)._"

    prompt = _build_ai_prompt(findings, summary, account_id)
    try:
        resp = requests.post(
            f"{host.rstrip('/')}/api/generate",
            json={"model": model, "prompt": prompt, "stream": False},
            timeout=180,  # local models on CPU can be slow — give it room
        )
        resp.raise_for_status()
        data = resp.json()
        text = data.get("response", "").strip()
        return text if text else "_AI summary returned no content._"
    except requests.exceptions.ConnectionError:
        return (f"_AI summary failed: could not reach Ollama at {host}. "
                f"Make sure it's running (`ollama serve` or `ollama run {model}`)._")
    except requests.exceptions.HTTPError as e:
        if resp.status_code == 404:
            return (f"_AI summary failed: model '{model}' not found in Ollama. "
                    f"Pull it first: `ollama pull {model}`._")
        return f"_AI summary failed: {e}_"
    except Exception as e:
        return f"_AI summary failed: {e}_"


def generate_ai_summary_any(findings, summary, account_id, provider="anthropic",
                             model=None, ollama_host="http://localhost:11434"):
    """Dispatches to the selected AI provider."""
    if provider == "ollama":
        return generate_ai_summary_ollama(findings, summary, account_id,
                                           model=model or "llama3.1", host=ollama_host)
    return generate_ai_summary_anthropic(findings, summary, account_id,
                                          model=model or "claude-sonnet-5")


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------

def render_markdown(findings, summary, generated_at, account_id, regions, ai_summary=None):
    lines = ["# AWS Security Group Risk Report", "",
              f"Generated: {generated_at}",
              f"Account: {account_id}",
              f"Regions scanned: {', '.join(regions)}", ""]
    if ai_summary:
        lines += ["## AI-generated executive summary", "", ai_summary, ""]
    lines += ["## Summary", "",
              f"- **Security groups analyzed:** {summary['total_sgs']}",
              f"- **Total findings:** {summary['total_findings']}"]
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        n = summary["by_severity"].get(sev, 0)
        if n:
            lines.append(f"  - {sev}: {n}")
    lines.append(f"- **Apparently unused security groups:** {summary['unused_sgs']}")
    lines.append("")

    if not findings:
        lines.append("No issues found.")
        return "\n".join(lines)

    lines.append("## Findings")
    lines.append("")
    current_sg = None
    for f in findings:
        header = f"{f['region']} — {f['sg_id']} ({f['sg_name']})"
        if header != current_sg:
            lines.append(f"### {header}")
            lines.append("")
            current_sg = header
        lines.append(f"**[{f['severity']}] {f['title']}**  \n"
                      f"*Category:* {f['category']}  \n"
                      f"*Detail:* {f['detail']}  \n"
                      f"*Remediation:* {f['remediation']}")
        lines.append("")
    return "\n".join(lines)


def render_html(findings, summary, generated_at, account_id, regions, ai_summary=None):
    sev_color = {"CRITICAL": "#b91c1c", "HIGH": "#c2410c", "MEDIUM": "#b45309",
                 "LOW": "#0369a1", "INFO": "#4b5563"}
    rows, current_sg = [], None
    for f in findings:
        header = f"{f['region']} — {f['sg_id']} ({f['sg_name']})"
        if header != current_sg:
            rows.append(f'<tr><td colspan="4" style="background:#f3f4f6;font-weight:600;padding:8px;">{header}</td></tr>')
            current_sg = header
        color = sev_color.get(f["severity"], "#4b5563")
        rows.append(f"""<tr>
<td style="padding:8px;"><span style="color:#fff;background:{color};padding:2px 8px;border-radius:4px;font-size:12px;font-weight:600;">{f['severity']}</span></td>
<td style="padding:8px;"><strong>{f['title']}</strong><br><span style="color:#6b7280;font-size:13px;">{f['category']}</span></td>
<td style="padding:8px;font-size:13px;">{f['detail']}</td>
<td style="padding:8px;font-size:13px;">{f['remediation']}</td>
</tr>""")

    summary_rows = "".join(f"<li>{sev}: {summary['by_severity'].get(sev,0)}</li>"
                            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] if summary["by_severity"].get(sev))
    ai_html = f"<h2>AI-generated executive summary</h2><p style='white-space:pre-wrap'>{ai_summary}</p>" if ai_summary else ""

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Security Group Risk Report</title></head>
<body style="font-family:-apple-system,Segoe UI,Arial,sans-serif;max-width:1100px;margin:40px auto;color:#111827;">
<h1>AWS Security Group Risk Report</h1>
<p style="color:#6b7280;">Generated: {generated_at}<br>Account: {account_id}<br>Regions: {', '.join(regions)}</p>
{ai_html}
<h2>Summary</h2>
<ul>
<li>Security groups analyzed: {summary['total_sgs']}</li>
<li>Total findings: {summary['total_findings']}</li>
{summary_rows}
<li>Apparently unused security groups: {summary['unused_sgs']}</li>
</ul>
<h2>Findings</h2>
<table style="border-collapse:collapse;width:100%;font-size:14px;">
<thead><tr style="border-bottom:2px solid #111827;text-align:left;">
<th style="padding:8px;">Severity</th><th style="padding:8px;">Finding</th><th style="padding:8px;">Detail</th><th style="padding:8px;">Remediation</th>
</tr></thead>
<tbody>{''.join(rows)}</tbody>
</table>
</body></html>"""


def write_csv(findings, path):
    fields = ["region", "sg_id", "sg_name", "vpc_id", "severity", "category", "title", "detail", "remediation"]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in findings:
            writer.writerow(row)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="AWS Security Group Risk Analyzer — run on demand, any time")
    parser.add_argument("--profile", help="AWS CLI profile to use (default: default profile / env vars)")
    parser.add_argument("--region", help="Single region to scan (default: your configured region)")
    parser.add_argument("--all-regions", action="store_true", help="Scan every enabled region in the account")
    parser.add_argument("--output", default="sg_risk_report.md", help="Output report path")
    parser.add_argument("--format", choices=["md", "html"], default="md", help="Report format")
    parser.add_argument("--csv", help="Optional path to also write findings as CSV")
    parser.add_argument("--json", dest="json_out", help="Optional path to write a findings JSON file (for the dashboard)")
    parser.add_argument("--ai", action="store_true", help="Generate an AI executive summary")
    parser.add_argument("--ai-provider", choices=["anthropic", "ollama"], default="anthropic",
                         help="Which AI backend to use for --ai (default: anthropic)")
    parser.add_argument("--model", help="Model id: Claude model name (anthropic) or Ollama model tag (ollama)")
    parser.add_argument("--ollama-host", default="http://localhost:11434",
                         help="Ollama server URL (default: http://localhost:11434)")
    args = parser.parse_args()

    try:
        session = get_session(args.profile, args.region)
        account_id, caller_arn = get_account_context(session)
    except RuntimeError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
    print(f"Authenticated as {caller_arn}")

    regions = list_target_regions(session, args.all_regions, args.region)
    print(f"Scanning {len(regions)} region(s): {', '.join(regions)}")

    all_findings, total_sgs, total_unused = [], 0, 0
    for region in regions:
        try:
            sgs = fetch_security_groups(session, region)
            enis = fetch_network_interfaces(session, region)
        except ClientError as e:
            print(f"  Skipping {region}: {e}", file=sys.stderr)
            continue
        usage_map = build_sg_usage_map(enis)
        findings = analyze_all(sgs, usage_map, region)
        all_findings.extend(findings)
        total_sgs += len(sgs)
        total_unused += sum(1 for sg in sgs if sg.get("GroupName") != "default" and not usage_map.get(sg.get("GroupId"), []))
        print(f"  {region}: {len(sgs)} security groups, {len(findings)} findings")

    all_findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["region"], f["sg_id"]))
    summary = summarize(all_findings, total_sgs, total_unused)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    ai_summary = None
    if args.ai:
        print(f"Generating AI executive summary via {args.ai_provider}...")
        ai_summary = generate_ai_summary_any(all_findings, summary, account_id,
                                              provider=args.ai_provider, model=args.model,
                                              ollama_host=args.ollama_host)

    report = (render_markdown if args.format == "md" else render_html)(
        all_findings, summary, generated_at, account_id, regions, ai_summary)

    with open(args.output, "w") as f:
        f.write(report)
    if args.csv:
        write_csv(all_findings, args.csv)

    if args.json_out:
        dashboard_payload = {
            "generated_at": generated_at,
            "account_id": account_id,
            "regions": regions,
            "summary": summary,
            "ai_summary": ai_summary,
            "findings": all_findings,
        }
        with open(args.json_out, "w") as f:
            json.dump(dashboard_payload, f, indent=2)

    print(f"\nDone: {summary['total_sgs']} security groups scanned, {summary['total_findings']} findings.")
    print(f"Report: {args.output}")
    if args.csv:
        print(f"CSV: {args.csv}")
    if args.json_out:
        print(f"Dashboard JSON: {args.json_out}")


if __name__ == "__main__":
    main()
