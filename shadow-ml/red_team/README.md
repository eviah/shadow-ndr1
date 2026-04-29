# Shadow NDR — Red-Team Validation Harness

Pre-pentest hardening tool. Fires every attack technique your detectors are
supposed to catch — auth, tenant isolation, injection, rate limits, ADS-B
spoofing, industrial protocol abuse, exfil, beaconing, evasion — at your
own localhost stack and tells you what got caught and what slipped past.

> **Scope is enforced.** Every request goes through [`safety.py`](safety.py).
> Targets outside `localhost` / your docker net are **rejected at runtime**.
> This harness will not, and structurally cannot, attack a third party.

## What it does NOT do

- No real CVE exploits, no shellcode, no working RCE
- No worm propagation / lateral spreading off-host
- No destructive payloads (`DROP TABLE`, `rm -rf`, etc. — those are *shape* probes only)
- No credential theft / exfil to external endpoints
- No DoS — global rate cap defaults to 25 req/sec

## Quick start

```bash
# 1. Make sure the MT backend is up on :3001 and shadow-ml on :8000
# 2. (optional) export creds for tenant-isolation tests
export RT_USER=elal_admin
export RT_PASS=<your-test-password>

# 3. Dry-run first to see what will fire
python -m red_team.adversary --campaign all --dry-run --verbose

# 4. Real run with detection scoring
python -m red_team.adversary --campaign all --score -o report.json
```

## Campaigns

| campaign | what it exercises |
|----------|-------------------|
| `auth` | brute force, JWT tamper, refresh abuse, timing leaks, malformed bodies |
| `tenant` | cross-tenant header injection, IDOR on `/api/assets/:id`, `/api/threats/:id` |
| `injection` | SQLi/XSS/path-traversal/SSRF/cmd-inject/proto-pollution shapes |
| `ratelimit` | X-Forwarded-For spoofing, header rotation, login burst |
| `adsb` | impossible kinematics, ICAO impersonation, GPS jumps, ghost swarm, replay |
| `industrial` | Modbus function-code abuse, IEC-104 APCI flood, DNP3 unsolicited, OPC-UA oversize |
| `lateral` | threat flood, bulk-ack spam, RBAC-bypass DELETE probes |
| `exfil` | repeated full exports, fast polling |
| `beacon` | fixed-cadence callbacks (C2 timing pattern) |
| `evasion` | slow-drip, jittered, user-agent fuzz |
| `all` | every campaign sequentially |

## Output

`report.json` contains:
- per-attack record (technique, URL, status, latency)
- summary by technique (counts of 2xx/4xx/5xx/error)
- when `--score` is set: detection coverage % + list of missed techniques

Aim for **100% coverage** before the pentest. Every entry in `missed_techniques`
is a detection gap to fix.

## Pre-flight checklist (the day of the pentest)

```bash
# 1. Snapshot the DB so you can roll back the noise
docker exec shadow-postgres pg_dump -U shadow shadow_ndr_mt > pre-rt.sql

# 2. Run the harness
python -m red_team.adversary --campaign all --score --rate 50 -o pre-pentest.json

# 3. Review missed_techniques — fix detection gaps
jq '.summary.detection.missed_techniques' pre-pentest.json

# 4. Re-run after fixes
python -m red_team.adversary --campaign all --score -o post-fix.json

# 5. Restore DB if you want a clean slate before the real test
docker exec -i shadow-postgres psql -U shadow shadow_ndr_mt < pre-rt.sql
```

## Stealth mode

```bash
python -m red_team.adversary --campaign auth --stealth --rate 1
```

Slow-drip (2-8x random gap between requests). Tests whether your behavior
analytics catch low-and-slow without burst signals.

## Safety override (LAN testing)

By default only loopback is allowed. To target a private RFC1918 IP on a
machine you own:

```bash
export RED_TEAM_ALLOW_PRIVATE_LAN=i-own-this
python -m red_team.adversary --backend http://192.168.1.50:3001 ...
```

Public IPs are **never** allowed regardless of env vars — modify
[`safety.py`](safety.py) directly if you need that, and accept the legal
weight of doing so.
