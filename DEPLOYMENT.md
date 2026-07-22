# Deploying the Dashboard for Your Whole Team

This turns the dashboard from "runs on my laptop" into "one URL the team
bookmarks." Recommended shape:

```
Teammates' browsers
        │  HTTPS + login prompt
        ▼
   nginx (reverse proxy, TLS + basic auth)
        │  internal Docker network only
        ▼
   app.py (gunicorn, 4 workers)
        │  boto3, using the SERVER's IAM role — no personal AWS keys
        ▼
   AWS APIs (read-only)
```

One server, one IAM role, one login shared by the team — nobody needs
their own AWS credentials or Python environment set up.

---

## 1. Pick a host

Any always-on Linux machine with Docker works: an EC2 instance, an
internal VM, etc. This guide assumes EC2 since that's the most common
choice, but the steps are the same anywhere Docker runs.

- Instance size: small is fine (t3.small/medium) — the work is mostly
  waiting on AWS API responses, not CPU, unless you also run a local
  Ollama model, in which case size for that model's requirements instead.
- Security group: only open 443 (and 80, which just redirects to 443) to
  your office/VPN CIDR — not `0.0.0.0/0`. This dashboard has no user
  accounts of its own beyond the shared login, so don't expose it publicly.

## 2. Create an IAM role for the server (not individual users)

This is the important part — it's *why* teammates won't need their own
AWS credentials. Create a role (e.g. `sg-dashboard-role`) with:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DescribeRegions",
      "sts:GetCallerIdentity"
    ],
    "Resource": "*"
  }]
}
```

Attach it as the instance profile on your EC2 host. `boto3` inside the
container will pick it up automatically via the instance metadata service
— no keys in any config file.

> **Docker + IMDS note:** if `boto3` inside the container can't see the
> role, it's usually the metadata hop limit. Fix with:
> ```bash
> aws ec2 modify-instance-metadata-options --instance-id <id> --http-put-response-hop-limit 2 --http-endpoint enabled
> ```

## 3. Get the files onto the server

Copy the whole project folder over (scp, git clone, etc.) so it contains:
```
app.py  sg_risk_analyzer_live.py  dashboard.html  sample_findings.json
requirements.txt  Dockerfile  docker-compose.yml  nginx.conf
```

## 4. Set up the team login

```bash
sudo apt-get install -y apache2-utils   # provides the htpasswd tool
htpasswd -c .htpasswd alice             # -c only on the FIRST user
htpasswd .htpasswd bob                  # no -c for subsequent users
htpasswd .htpasswd carol
```

This creates `.htpasswd`, which `docker-compose.yml` mounts into nginx.
Anyone hitting the dashboard gets a browser login prompt for these
credentials. (If your org uses SSO, swap the `auth_basic` block in
`nginx.conf` for an OAuth2 proxy instead — ask your identity/security team
which pattern they prefer.)

## 5. Get a TLS certificate

Pick whichever is easiest for your setup:
- **Simplest on AWS:** put an Application Load Balancer with an ACM
  certificate in front of the instance instead of terminating TLS in
  nginx yourself. Point the ALB at port 80 on the instance, and remove
  the `ssl_certificate` lines from `nginx.conf` (ALB handles HTTPS).
- **Public domain, no ALB:** use `certbot` (Let's Encrypt) on the host,
  then mount the resulting cert/key into `./certs/` for nginx to use as-is.
- **Internal-only:** use your internal CA, or a self-signed cert if the
  team's browsers will tolerate the warning (fine for internal tools,
  not ideal — a real cert is one certbot command away if you have a domain).

## 6. Set environment variables (optional)

```bash
# Only if you're using Claude instead of/alongside a local model:
export ANTHROPIC_API_KEY=sk-ant-...

# Only if NOT using the IAM instance role (not recommended, but supported):
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
```

## 7. Build and start

```bash
docker compose up -d --build
docker compose logs -f app   # watch it come up
```

Visit `https://your-server/` from a teammate's browser — you should get
the login prompt, then the dashboard.

## 8. Updating later

```bash
git pull          # or however you sync new file versions
docker compose up -d --build
```

`restart: unless-stopped` in the compose file means it also survives host
reboots without manual intervention.

---

## Offering a shared local AI model instead of Claude

If you'd rather the whole team use one local Ollama model instead of an
Anthropic API key, uncomment the `ollama` service in `docker-compose.yml`
and set:
```bash
export OLLAMA_HOST=http://ollama:11434
```
Then pull a model into it once:
```bash
docker compose exec ollama ollama pull llama3.1
```
Teammates can then just tick "Ollama" in Settings without typing a host —
the server already defaults to the shared instance.

---

## Not using Docker?

The same idea works without containers: install `gunicorn` alongside the
other dependencies, run it as a `systemd` service so it restarts on boot
and on crash, and put your organization's existing nginx/Apache/ALB in
front of it the same way. The only two things that matter regardless of
how you host it:
1. **An IAM role or shared credential on the server**, not per-user keys.
2. **Something in front of `app.py` that requires a login** — it has none
   of its own by design, since it was built to run on a single trusted
   machine.
