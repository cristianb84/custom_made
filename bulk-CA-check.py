#!/usr/bin/env python3

import sys
import subprocess
import re

def strip_ansi_codes(text):
    ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
    return ansi_escape.sub('', text)

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} target_file")
        sys.exit(1)

    target_file = sys.argv[1]

    try:
        with open(target_file, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"File '{target_file}' not found.")
        sys.exit(1)

    for target in targets:
        cmd = [
            '/opt/OWASP/wstg/testssl.sh/testssl.sh',
            '--quiet',
            '--color', '0',
            '-S',
            target
        ]
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,  # Capture both stdout and stderr
                text=True
            )
        except Exception as e:
            print(f"Error running testssl.sh on {target}: {e}")
            continue

        output = result.stdout
        output = strip_ansi_codes(output)
        lines = output.split('\n')

        # For debugging: Uncomment the following line to see the raw output
        # print(f"Output for {target}:\n{output}\n{'-'*60}")

        # Check for connection errors
        connection_refused = any(
            "Connection refused" in line or "Can't connect" in line for line in lines
        )
        connection_timed_out = any(
            "Connection timed out" in line or "Can't connect" in line for line in lines
        )

        if connection_refused:
            print(f"Target: {target}")
            print("Error: Connection refused.")
            print('-' * 40)
            continue
        elif connection_timed_out:
            print(f"Target: {target}")
            print("Error: Connection timed out.")
            print('-' * 40)
            continue

        chain_of_trust = "Not found"
        certificate_validity = "Not found"
        issuer = "Not found"

        for i in range(len(lines)):
            line = lines[i].strip()
            if line.startswith('Chain of trust'):
                chain_of_trust = line[len('Chain of trust'):].strip()
            elif line.startswith('Certificate Validity'):
                certificate_validity = line[len('Certificate Validity'):].strip()
                # Check for additional validity info on the next lines
                j = i + 1
                while j < len(lines):
                    next_line = lines[j].strip()
                    if next_line.startswith('(') or next_line.startswith('>='):
                        certificate_validity += ' ' + next_line
                        j += 1
                    else:
                        break
            elif line.startswith('Issuer'):
                issuer = line[len('Issuer'):].strip()

        print(f"Target: {target}")
        print(f"Chain of trust: {chain_of_trust}")
        print(f"Certificate Validity: {certificate_validity}")
        print(f"Issuer: {issuer}")
        print('-' * 40)

if __name__ == "__main__":
    main()
