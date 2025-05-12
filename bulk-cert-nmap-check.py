#!/usr/bin/env python3
import subprocess
from datetime import datetime
import argparse

# ANSI helpers
def red(text):
    return f"\033[31m{text}\033[0m"

def green(text):
    return f"\033[32m{text}\033[0m"

def parse_cert_output(stdout):
    subject = san = issuer = None
    not_before = not_after = None

    for raw in stdout.splitlines():
        line = raw.lstrip("| ").strip()
        if line.startswith("ssl-cert:"):
            line = line.split("ssl-cert:", 1)[1].strip()

        if line.startswith("Subject:"):
            subject = line.split("Subject:", 1)[1].strip()
        elif line.startswith("Subject Alternative Name:"):
            san = line.split("Subject Alternative Name:", 1)[1].strip()
        elif line.startswith("Issuer:"):
            issuer = line.split("Issuer:", 1)[1].strip()
        elif line.startswith("Not valid before:"):
            not_before = line.split("Not valid before:", 1)[1].strip()
        elif line.startswith("Not valid after:"):
            not_after = line.split("Not valid after:", 1)[1].strip()

    return subject, san, issuer, not_before, not_after

def split_dn(dn):
    """Turn “commonName=foo/organizationName=bar” into a list of parts."""
    return dn.split('/') if dn else []

def check_cert(ip, port):
    cmd = ["nmap", "-Pn", "--script", "ssl-cert", f"-p{port}", ip]
    out, err = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).communicate()

    if "filtered" in out:
        return {"error": "Connection timeout"}
    if "closed" in out:
        return {"error": "Connection refused"}
    if "open" in out and "ssl-cert:" not in out:
        return {"error": "Certificate not found"}

    subject, san, issuer, nb, na = parse_cert_output(out)
    if not nb or not na:
        return {"error": "Certificate information not found"}

    na_dt = datetime.strptime(na, "%Y-%m-%dT%H:%M:%S")
    days = (na_dt - datetime.now()).days
    if days < 0:
        status_text = f"Expired {abs(days)} days ago"
        expired = True
    else:
        status_text = f"{days} days until expiry"
        expired = False

    return {
        "subject": split_dn(subject),
        "san": san,
        "issuer": split_dn(issuer),
        "not_before": nb,
        "not_after": na,
        "status_text": status_text,
        "expired": expired
    }

def main():
    p = argparse.ArgumentParser(description='Bulk certificate validity check.')
    p.add_argument('file', help='IP list, one per line, optionally with :port')
    p.add_argument('-p', '--ports', default='443',
                   help='Comma-separated list of default ports (default: 443)')
    args = p.parse_args()

    default_ports = list({*args.ports.split(',')})
    with open(args.file) as f:
        targets = [l.strip() for l in f if l.strip()]

    for entry in targets:
        ip, *pr = entry.split(':')
        ports = [pr[0]] if pr else default_ports
        for port in ports:
            info = check_cert(ip, port)
            header = f"{ip}:{port}"
            print(header)
            print("  " + "-" * len(header))

            if "error" in info:
                print(f"  Error     : {info['error']}\n")
                continue

            # Color the status and inline the validity window
            status_colored = red(info['status_text']) if info['expired'] else green(info['status_text'])
            print(f"  Status    : {status_colored} ({info['not_before']} -> {info['not_after']})")

            # Subject on one line, pipes between RDNs
            if info['subject']:
                subj_line = " | ".join(info['subject'])
                print(f"  Subject   : {subj_line}")

            # SAN as before
            if info['san']:
                print(f"  SAN       : {info['san']}")

            # Issuer on one line
            if info['issuer']:
                iss_line = " | ".join(info['issuer'])
                print(f"  Issuer    : {iss_line}")

            print()  # blank line between entries

if __name__ == "__main__":
    main()
