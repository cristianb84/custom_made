#!/usr/bin/env python3

import sys
import requests
import json
import subprocess
import os
import argparse
from bs4 import BeautifulSoup
import xml.etree.ElementTree as ET

# ANSI color codes
color_warning = "\033[38;5;208m"  # Similar to #f9a009
color_danger = "\033[31m"  # Red, similar to #ff0000
color_info = "\033[32m"  # Green, similar to the Info color
color_reset = "\033[0m"  # Reset to default color

# Color codes dictionary
color_codes = {'weak': color_warning,
               'insecure': color_danger,
               'secure': color_info,
               'recommended': color_info,
               'unknown': color_reset, 'not found': color_reset}


def colorize(text, color_code):
    return f"\033[{color_code}m{text}\033[0m"

def get_ciphers_from_url(tls_version):
    security_levels = ['recommended', 'secure']
    ciphers = []
    for security_level in security_levels:
        # Adjust the URL depending on the TLS version
        if tls_version == 'tls1.2':
            version_url = 'tls12'
        elif tls_version == 'tls1.3':
            version_url = 'xtls13'
        else:
            raise ValueError("Unsupported TLS version")
        url = f'https://ciphersuite.info/cs/?security={security_level}&tls={version_url}'
        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            cipher_elements = soup.select('ul.prettylist li a span.break-all')
            for element in cipher_elements:
                ciphers.append(element.text.strip())
    return ciphers

def check_for_updates(testssl_path):
    """
    Check for updates to testssl.sh using git pull.

    :param testssl_path: Path to the testssl.sh directory
    """
    try:
        # Navigate to testssl.sh directory
        os.chdir(testssl_path)

        # Check for updates
        result = subprocess.run(
            ["git", "pull"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if "Already up to date." not in result.stdout:
            print("Updating testssl.sh...")
            print(result.stdout)
        else:
            print("testssl.sh is up to date.")

    except Exception as e:
        print(f"Failed to check for updates to testssl.sh: {str(e)}")

def fetch_iana_tls_parameters():
    url = 'https://www.iana.org/assignments/tls-parameters/tls-parameters.xml'
    try:
        response = requests.get(url)
        response.raise_for_status()
        xml_content = response.content
        root = ET.fromstring(xml_content)
        root = remove_namespace(root)
        return root
    except requests.exceptions.RequestException as e:
        print(f"Error fetching IANA TLS parameters: {str(e)}")
        return None
    except ET.ParseError as e:
        print(f"Error parsing IANA TLS parameters XML: {str(e)}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")
        return None

def remove_namespace(doc):
    """Remove namespace prefixes from XML elements."""
    for elem in doc.iter():
        if '}' in elem.tag:
            elem.tag = elem.tag.split('}', 1)[1]
    return doc

def get_element_text(element):
    """Helper function to safely extract and strip text from an XML element."""
    if element is not None and element.text is not None:
        return element.text.strip()
    else:
        return 'Unknown'

def parse_iana_tls_parameters(root):
    cipher_mapping = {}
    # Parse only the 'TLS Cipher Suites' registry
    for registry in root.findall(".//registry"):
        title = registry.find('title')
        if title is not None and title.text == 'TLS Cipher Suites':
            # Now parse the records in this registry
            for record in registry.findall('record'):
                description = record.find('description')
                dtls = record.find('dtls')
                rec = record.find('rec')

                cipher_name = get_element_text(description)
                if cipher_name != 'Unknown':
                    dtls_value = get_element_text(dtls)
                    rec_value = get_element_text(rec)

                    cipher_mapping[cipher_name] = {
                        'dtls': dtls_value,
                        'rec': rec_value
                    }
            # Break after parsing the correct registry
            break
    return cipher_mapping

def get_iana_cipher_mapping():
    iana_root = fetch_iana_tls_parameters()
    if iana_root is not None:
        iana_cipher_mapping = parse_iana_tls_parameters(iana_root)
        return iana_cipher_mapping
    else:
        return {}

def get_security_level(cipher, iana_cipher_mapping):
    # Retrieve IANA information first
    iana_info = iana_cipher_mapping.get(cipher, {'dtls': 'Unknown', 'rec': 'Unknown'})
    dtls_value = iana_info['dtls']
    rec_value = iana_info['rec']

    # If IANA recommends the cipher, set security to 'Secure' and skip fetching alerts
    if rec_value == 'Y':
        security = 'Secure'
        alert_categories = {'Danger': [], 'Warning': [], 'Info': []}
    else:
        # Fetch security level and alerts from ciphersuite.info
        url = f'https://ciphersuite.info/cs/{cipher}/'
        try:
            response = requests.get(url)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')

                # Extracting the security level from ciphersuite.info
                badge_span = soup.find('span', class_='badge')
                security = badge_span.text.strip() if badge_span else 'Unknown'

                # Overriding security level if IANA recommends "N"
                if rec_value == 'N' and security.lower() == 'secure':
                    security = 'Weak'
                    alert_categories = {'Danger': [],
                                        'Warning': [("IANA not recommended", "The cipher is not recommended by IANA.")],
                                        'Info': []}
                else:
                    # Initializing alert categories
                    alert_categories = {'Danger': [], 'Warning': [], 'Info': []}

                    # Extracting alert details
                    alerts = soup.find_all('div', class_='alert')
                    for alert in alerts:
                        classes = alert.get('class', [])
                        if 'alert-danger' in classes:
                            category = 'Danger'
                        elif 'alert-warning' in classes:
                            category = 'Warning'
                        elif 'alert-info' in classes:
                            category = 'Info'
                        else:
                            category = 'Unknown'

                        strong_tag = alert.find('strong')
                        p_tag = alert.find('p')
                        if strong_tag and p_tag:
                            name = strong_tag.text.strip(': ')
                            description = p_tag.text.strip()
                            alert_categories.setdefault(category, []).append((name, description))
            else:
                security = 'Not Found'
                alert_categories = {}
        except Exception as e:
            print(f"Error retrieving cipher information: {str(e)}")
            security = 'Error'
            alert_categories = {}

    return security, alert_categories, dtls_value, rec_value

def list_iana_recommended_ciphers():
    iana_cipher_mapping = get_iana_cipher_mapping()
    if iana_cipher_mapping:
        print("Ciphers recommended by IANA:")
        # Sort ciphers alphabetically for better readability
        for cipher_name, data in sorted(iana_cipher_mapping.items()):
            if data['rec'] == 'Y':
                print(cipher_name)
    else:
        print("Failed to fetch or parse IANA TLS parameters.")

def find_testssl():
    # Step 1: Check globally
    result = subprocess.run(
        ["which", "testssl.sh"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.stdout.strip():
        print("testssl.sh found globally")
        return os.path.dirname(result.stdout.strip())

    # Step 2: Check common directories
    common_dirs = ["/opt/", "/usr/local/bin", os.path.expanduser("~")]
    for dir_path in common_dirs:
        for root, dirs, files in os.walk(dir_path):
            if "testssl.sh" in files:
                print(f"testssl.sh found in {root}")
                return root

    # Step 3: Ask user for path or to install
    print("testssl.sh not found.")
    user_action = input(
        "Do you want to provide a path to testssl.sh or should I try to install it for you? (provide/install/exit): ")

    if user_action.lower() == 'exit':
        exit()
    elif user_action.lower() == 'provide':
        user_path = input("Please provide the path to testssl.sh: ")
        if os.path.isdir(user_path) and "testssl.sh" in os.listdir(user_path):
            print(f"testssl.sh found in {user_path}")
            return user_path
        elif os.path.isfile(user_path) and "testssl.sh" in user_path:
            print(f"testssl.sh found at {user_path}")
            return os.path.dirname(user_path)
        else:
            print("Invalid path provided. Exiting.")
            exit()

    elif user_action.lower() == 'install':
        install_path = input("Please provide a path to install testssl.sh: ")
        if not os.path.exists(install_path):
            print("Invalid path provided. Exiting.")
            exit()

        # Create a new directory for testssl.sh in the provided path
        testssl_install_path = os.path.join(install_path, "testssl.sh")
        os.makedirs(testssl_install_path, exist_ok=True)

        print("Attempting to clone testssl.sh from GitHub...")
        result = subprocess.run(["git", "clone", "https://github.com/drwetter/testssl.sh.git", testssl_install_path],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            print("testssl.sh successfully installed.")
            return testssl_install_path
        else:
            print(f"Failed to install testssl.sh: {result.stderr}")
            exit()


def run_testssl(target, testssl_path, iana_cipher_mapping, light_mode=False, noinfo=False):
    color_warning = "\033[38;5;208m"  # Similar to #f9a009
    color_danger = "\033[31m"  # Red, similar to #ff0000
    color_info = "\033[32m"  # Green, similar to the Info color
    color_reset = "\033[0m"  # Reset to default color

    color_codes = {'weak': color_warning,
                   'insecure': color_danger,
                   'secure': color_info,
                   'recommended': color_info,
                   'unknown': color_reset, 'not found': color_reset}

    testssl_script = os.path.join(testssl_path, "testssl.sh")
    try:
        result = subprocess.run([testssl_script, "--warnings", "off", "-P", target],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                text=True)
        # Extract and check ciphers
        lines = result.stdout.splitlines()

        # Step 1: Extract cipher names and determine the maximum length
        cipher_names = [line.split()[-1] for line in lines if "TLS_" in line]
        if cipher_names:
            max_cipher_name_length = max(len(cipher_name) for cipher_name in cipher_names)
        else:
            max_cipher_name_length = 0

        # Set column widths
        cipher_col_width = max_cipher_name_length
        dtls_col_width = 8
        rec_col_width = 12
        sec_level_col_width = 15

        header_format = f"{{:<{cipher_col_width}}}  {{:<{dtls_col_width}}}  {{:<{rec_col_width}}}  {{:<{sec_level_col_width}}}  {{}}"
        data_format = f"{{:<{cipher_col_width}}}  {{:<{dtls_col_width}}}  {{:<{rec_col_width}}}  {{:<{sec_level_col_width}}}  {{}}"

        if light_mode:
            # Print header
            header_line1 = header_format.format('Cipher', 'DTLS-OK', 'Recommended', 'Security Level', 'Alerts')
            header_line2 = header_format.format(' ' * cipher_col_width, '(IANA)', '(IANA)', '', '')
            print(header_line1)
            print(header_line2)
            print('-' * len(header_line1))

        for line in lines:
            if "SSLv" in line or "TLSv1" in line:
                print(line)
            elif "TLS_" in line:
                parts = line.split()
                cipher = parts[-1]
                security_level, alert_categories, dtls_value, rec_value = get_security_level(cipher, iana_cipher_mapping)

                if security_level == 'Not Found':
                    print(f"{line}\tCipher not found on ciphersuite.info")
                    continue

                # Group and color alert names only
                colored_alerts = []
                for category in ['Danger', 'Warning', 'Info']:
                    if noinfo and category == 'Info':
                        continue  # Skip "Info" category
                    color_code = color_info if category == 'Info' else color_warning if category == 'Warning' else color_danger
                    alert_names = [alert[0] for alert in alert_categories[category]]
                    colored_alerts.extend([f"{color_code}{name}{color_reset}" for name in alert_names])

                # Color the security level
                level_color_code = color_codes.get(security_level.lower(), color_reset)
                colored_level = f"{level_color_code}{security_level}{color_reset}"

                # Check if there are any alerts to display
                if colored_alerts:
                    alert_info = f"[{'; '.join(colored_alerts)}]"
                else:
                    alert_info = ""

                if light_mode:
                    print(data_format.format(cipher, dtls_value, rec_value, colored_level, alert_info))
                else:
                    # For full mode, you can adjust the output as needed
                    print(f"{line}\tIANA DTLS-OK: {dtls_value}\tIANA Recommended: {rec_value}\t{colored_level}\t{alert_info}")
    except Exception as e:
        print(f"Failed to run testssl.sh: {str(e)}")


config_file_path = os.path.expanduser("~/.ciphers")
testssl_path = None

if os.path.exists(config_file_path):
    with open(config_file_path, 'r') as file:
        testssl_path = file.read().strip()
        if not os.path.exists(testssl_path):
            testssl_path = None

if testssl_path is None:
    testssl_path = find_testssl()
    with open(config_file_path, 'w') as file:
        file.write(testssl_path)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='A script to assess the security level of SSL/TLS ciphers used by a target system or a specific cipher.')
    parser.add_argument(
        '-t', '--target', help='The target system (ip:port)', default=None)
    parser.add_argument(
        '-c', '--cipher', help='Specific cipher to test', default=None)
    parser.add_argument(
	'-l', '--tls-version', help='Specify the TLS version to grab Secure and Recommended ciphers for (source: ciphersuite.info) or "IANA" for IANA recommended ciphers.', choices=['TLS1.2', 'TLS1.3', 'IANA'], default=None)
    parser.add_argument(
        '-light', '--light', action='store_true', help='Output just the essential information: cipher, IANA DTLS-OK, IANA Recommended, security status, and alerts', default=None)
    parser.add_argument(
        '--noinfo', action='store_true', help='Do not include "Info" category in the alert output', default=None)
    parser.add_argument(
        '--list-iana-recommended', action='store_true', help='List all ciphers that are recommended according to IANA', default=None)

    args = parser.parse_args()
    light_mode = args.light

    # Fetch and parse IANA TLS parameters upfront if needed
    if args.tls_version == 'IANA' or args.cipher or args.target:
        iana_cipher_mapping = get_iana_cipher_mapping()
        if not iana_cipher_mapping:
            sys.exit("Failed to fetch or parse IANA TLS parameters.")

    if args.tls_version == 'IANA':
        if iana_cipher_mapping:
            print("Ciphers recommended by IANA:")
            # Sort ciphers alphabetically for better readability
            for cipher_name, data in sorted(iana_cipher_mapping.items()):
                if data['rec'] == 'Y':
                    print(cipher_name)
        else:
            print("Failed to fetch IANA TLS parameters.")
        sys.exit(0)

    elif args.cipher:
        # Test a specific cipher
        security_level, alert_categories, dtls_value, rec_value = get_security_level(args.cipher, iana_cipher_mapping)

        # ANSI color codes
        color_warning = "\033[38;5;208m"  # Similar to #f9a009
        color_danger = "\033[31m"  # Red, similar to #ff0000
        color_info = "\033[32m"  # Green, similar to the Info color
        color_reset = "\033[0m"  # Reset to default color

        # Color the security level
        level_color_code = color_codes.get(security_level.lower(), color_reset)
        colored_level = f"{level_color_code}{security_level}{color_reset}"

        print(f"Cipher: {args.cipher}")
        print(f"IANA DTLS-OK: {dtls_value}")
        print(f"IANA Recommended: {rec_value}")
        print(f"Security Level: {colored_level}\n")

        # Print alert details with colors
        for category in ['Danger', 'Warning', 'Info']:
            if args.noinfo and category == 'Info':
                continue  # Skip "Info" category
            color_code = color_info if category == 'Info' else color_warning if category == 'Warning' else color_danger
            for alert in alert_categories[category]:
                if isinstance(alert, tuple) and len(alert) == 2:
                    name, description = alert
                elif isinstance(alert, str):
                    name = alert
                    description = "Description not available"
                else:
                    print(f"Unexpected alert format: {alert}")
                    continue

                colored_name = f"{color_code}{name}{color_reset}"
                print(f"{colored_name}\nDescription: {description}\n")
    elif args.target:
        # Ensure testssl_path is set
        config_file_path = os.path.expanduser("~/.ciphers")
        testssl_path = None

        if os.path.exists(config_file_path):
            with open(config_file_path, 'r') as file:
                testssl_path = file.read().strip()
                if not os.path.exists(testssl_path):
                    testssl_path = None

        if testssl_path is None:
            testssl_path = find_testssl()
            with open(config_file_path, 'w') as file:
                file.write(testssl_path)

        # Check for updates and run testssl.sh
        check_for_updates(testssl_path)
        run_testssl(args.target, testssl_path, iana_cipher_mapping, light_mode=args.light, noinfo=args.noinfo)
    elif args.tls_version:
        tls_version = args.tls_version.replace('TLS', 'tls')  # Convert TLS1.2 or TLS1.3 to tls12 or tls13
        ciphers = get_ciphers_from_url(tls_version)
        for cipher in ciphers:
            print(cipher)
    else:
        parser.print_help(sys.stderr)
        sys.exit(1)
