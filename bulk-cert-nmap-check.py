#!/usr/bin/env python3
import subprocess
from datetime import datetime
import argparse

# ANSI helpers
def red(text):   return f"\033[31m{text}\033[0m"
def green(text): return f"\033[32m{text}\033[0m"

def parse_cert_output(stdout):
    subject = san = issuer = None
    not_before = not_after = None
    for raw in stdout.splitlines():
        line = raw.lstrip("| ").strip()
        if line.startswith("ssl-cert:"):
            line = line.split("ssl-cert:",1)[1].strip()
        if line.startswith("Subject:"):
            subject = line.split("Subject:",1)[1].strip()
        elif line.startswith("Subject Alternative Name:"):
            san = line.split("Subject Alternative Name:",1)[1].strip()
        elif line.startswith("Issuer:"):
            issuer = line.split("Issuer:",1)[1].strip()
        elif line.startswith("Not valid before:"):
            not_before = line.split("Not valid before:",1)[1].strip()
        elif line.startswith("Not valid after:"):
            not_after = line.split("Not valid after:",1)[1].strip()
    return subject, san, issuer, not_before, not_after

def split_dn(dn):
    return dn.split('/') if dn else []

def check_cert(ip, port):
    cmd = ["nmap","-Pn","--script","ssl-cert",f"-p{port}",ip]
    out, _ = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE,
                              text=True).communicate()

    if "filtered" in out:            return {"error":"Connection timeout"}
    if "closed" in out:              return {"error":"Connection refused"}
    if "open" in out and "ssl-cert:" not in out:
        return {"error":"Certificate not found"}

    subject, san, issuer, nb, na = parse_cert_output(out)
    if not nb or not na:
        return {"error":"Certificate information not found"}

    na_dt = datetime.strptime(na, "%Y-%m-%dT%H:%M:%S")
    days = (na_dt - datetime.now()).days
    if days < 0:
        status_text = f"Expired {abs(days)} days ago"
        expired = True
    else:
        status_text = f"{days} days until expiry"
        expired = False

    return {
        "subject"    : split_dn(subject),
        "san"        : san,
        "issuer"     : split_dn(issuer),
        "not_before" : nb,
        "not_after"  : na,
        "status_text": status_text,
        "expired"    : expired
    }

def main():
    p = argparse.ArgumentParser(description='Bulk certificate validity check.')
    p.add_argument('-f','--fields',
                   help='Comma-separated fields: status,subject,san,issuer')
    p.add_argument('-p','--ports', default='443',
                   help='Comma-separated default ports (default: 443)')
    p.add_argument('file', help='IP list, one per line, optionally with :port')
    args = p.parse_args()

    if args.fields:
        wanted = {f.strip().lower() for f in args.fields.split(',')}
    else:
        wanted = None  # means “all”

    default_ports = list({*args.ports.split(',')})
    targets = []
    with open(args.file) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            ip, *pr = line.split(':')
            ports = [pr[0]] if pr else default_ports
            for port in ports:
                targets.append((ip, port))

    labels_colon = [f"{ip}:{port} ->" for ip,port in targets]
    max_lbl = max(len(lbl) for lbl in labels_colon)

    for (ip,port), lbl in zip(targets, labels_colon):
        info = check_cert(ip, port)

        out_lines = []
        if "error" in info:
            out_lines.append(f"Error     : {info['error']}")
        else:
            if wanted is None or 'status' in wanted:
                st = red(info['status_text']) if info['expired'] else green(info['status_text'])
                out_lines.append(f"Status    : {st} ({info['not_before']} -> {info['not_after']})")
            if wanted is None or 'subject' in wanted:
                if info['subject']:
                    out_lines.append(f"Subject   : {' | '.join(info['subject'])}")
            if wanted is None or 'san' in wanted:
                if info['san']:
                    out_lines.append(f"SAN       : {info['san']}")
            if wanted is None or 'issuer' in wanted:
                if info['issuer']:
                    out_lines.append(f"Issuer    : {' | '.join(info['issuer'])}")

        pad = ' ' * (max_lbl - len(lbl) + 1)
        print(f"{lbl}{pad}{out_lines[0]}")
        indent = ' ' * (max_lbl + 1)
        for extra in out_lines[1:]:
            print(f"{indent}{extra}")

if __name__ == "__main__":
    main()
