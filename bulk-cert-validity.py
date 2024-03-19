import subprocess
import sys
from datetime import datetime, timedelta
import argparse


def check_cert(ip, port):  # Updated this line
    command = ["nmap", "-Pn", "--script", "ssl-cert", f"-p{port}", ip]
    process = subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = process.communicate()

    if "filtered" in stdout:
        return "Connection timeout"
    elif "closed" in stdout:
        return "Connection refused"
    elif "open" in stdout and "ssl-cert:" not in stdout:
        return "Certificate not found"
    else:
        not_before = not_after = None  # Initialize variables to None
        for line in stdout.split('\n'):
            if "Not valid before:" in line:
                not_before = line.split()[-1]
            if "Not valid after: " in line:
                not_after = line.split()[-1]
                break  # Exit the loop once we find the 'Not valid after' line

        if not_before is None or not_after is None:
            return "Certificate information not found"

        not_after_date = datetime.strptime(not_after, "%Y-%m-%dT%H:%M:%S")
        now = datetime.now()
        days_to_expire = (not_after_date - now).days
        validity = f"({not_before} --> {not_after})"

        if days_to_expire < 0:
            expired_text = "\033[31mexpired\033[0m"  # Red text
            return f"Certificate Validity {expired_text} {validity}"
        else:
            days_text = f"\033[32m{days_to_expire} days\033[0m"  # Green text
            return f"Certificate Validity {days_text} {validity}"


def main():
    parser = argparse.ArgumentParser(
        description='Bulk certificate validity check.')
    parser.add_argument(
        'file', help='File containing IP addresses, one per line, optionally followed by :port.')
    parser.add_argument('-p', '--ports', default='443',
                        help='Comma-separated list of ports to check. Default is 443.')
    args = parser.parse_args()

    # Remove duplicates by converting to a set and back to a list
    default_ports = list(set(args.ports.split(',')))

    with open(args.file, 'r') as file:
        ips_ports = file.read().strip().split('\n')

    for ip_port in ips_ports:
        ip, *port_details = ip_port.split(':')
        port = port_details[0] if port_details else None
        if port is None:
            for port in default_ports:
                result = check_cert(ip, port)
                print(f"{ip}:{port} -> {result}")
        else:
            result = check_cert(ip, port)
            print(f"{ip}:{port} -> {result}")


if __name__ == "__main__":
    main()
