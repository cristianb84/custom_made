import sys
import requests
import json
import subprocess
import os
import argparse
from bs4 import BeautifulSoup


def colorize(text, color_code):
    return f"\033[{color_code}m{text}\033[0m"


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


def get_security_level(cipher):
    url = f'https://ciphersuite.info/cs/{cipher}/'
    try:
        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')

            # Extracting the security level
            badge_span = soup.find('span', class_='badge')
            security = badge_span.text.strip() if badge_span else 'Unknown'

            # Initializing alert categories
            alert_categories = {'Danger': [], 'Warning': [], 'Info': []}

            # Extracting alert details
            alerts = soup.find_all('div', class_='alert')
            for alert in alerts:
                category = 'Danger' if 'alert-danger' in alert.get(
                    'class', []) else 'Warning' if 'alert-warning' in alert.get('class', []) else 'Info'
                strong_tag = alert.find('strong')
                p_tag = alert.find('p')
                if strong_tag and p_tag:
                    name = strong_tag.text.strip(': ')
                    description = p_tag.text.strip()
                    alert_categories[category].append((name, description))

            return security, alert_categories
        else:
            return 'Unavailable', {}
    except Exception as e:
        print(f"Error retrieving cipher information: {str(e)}")
        return 'Error', {}


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

def run_testssl(target, testssl_path):
    color_warning = "\033[38;5;208m"  # Similar to #f9a009
    color_danger = "\033[31m"  # Red, similar to #ff0000
    color_info = "\033[32m"  # Green, similar to the Info color
    color_reset = "\033[0m"  # Reset to default color

    color_codes = {'Weak': color_warning, 'Insecure': color_danger, 'Secure': color_info, 'Recommended': color_info, 'Unknown': color_reset}

    testssl_script = os.path.join(testssl_path, "testssl.sh")
    try:
        result = subprocess.run([testssl_script, "--warnings", "off", "-P", target],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                text=True)
        # Extract and check ciphers
        lines = result.stdout.splitlines()
        for line in lines:
            if "SSLv" in line or "TLSv1" in line:
                print(line)
            elif "TLS_" in line:
                parts = line.split()
                cipher = parts[-1]
                security_level, alert_categories = get_security_level(cipher)

                # Group and color alert names only
                colored_alerts = []
                for category in ['Danger', 'Warning', 'Info']:
                    color_code = color_info if category == 'Info' else color_warning if category == 'Warning' else color_danger
                    alert_names = [alert[0] for alert in alert_categories[category]]
                    colored_alerts.extend(
                        [f"{color_code}{name}{color_reset}" for name in alert_names])

                # Color the security level
                level_color = color_codes.get(security_level, color_reset)
                colored_level = f"{level_color}{security_level}{color_reset}"

                print(f"{line}\t{colored_level} [{'; '.join(colored_alerts)}]")
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

    args = parser.parse_args()

    if args.cipher:
        # Test a specific cipher
        security_level, alert_categories = get_security_level(args.cipher)

        # ANSI color codes
        color_warning = "\033[38;5;208m"  # Similar to #f9a009
        color_danger = "\033[31m"  # Red, similar to #ff0000
        color_info = "\033[32m"  # Green, similar to the Info color
        color_reset = "\033[0m"  # Reset to default color

        # Color the security level
        level_color = color_info if security_level in [
            'secure', 'recommended'] else color_warning if security_level == 'weak' else color_danger if security_level == 'insecure' else color_reset
        colored_level = f"{level_color}{security_level}{color_reset}"
        color_codes = {'Weak': '38;5;208', 'Insecure': '31',
                       'Secure': '32', 'Recommended': '32', 'Unknown': '0'}

        print(f"Cipher: {args.cipher}")
        print(
            f"Security Level: {colorize(security_level, color_codes.get(security_level, '0'))}\n")

        # Print alert details with colors
        for category in ['Danger', 'Warning', 'Info']:
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
                print(f"\n{colored_name}\nDescription: {description}\n")
    elif args.target:
        # Check for updates and run testssl.sh
        check_for_updates(testssl_path)
        run_testssl(args.target, testssl_path)
    else:
        parser.print_help(sys.stderr)
        sys.exit(1)
