import sys
import requests
import json
import subprocess
import os
import argparse

def check_for_updates(testssl_path):
    """
    Check for updates to testssl.sh using git pull.
    
    :param testssl_path: Path to the testssl.sh directory
    """
    try:
        # Navigate to testssl.sh directory
        os.chdir(testssl_path)
        
        # Check for updates
        result = subprocess.run(["git", "pull"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if "Already up to date." not in result.stdout:
            print("Updating testssl.sh...")
            print(result.stdout)
        else:
            print("testssl.sh is up to date.")
        
    except Exception as e:
        print(f"Failed to check for updates to testssl.sh: {str(e)}")

def get_security_level(cipher):
    response = requests.get(f'https://ciphersuite.info/api/cs/{cipher}/')
    if response.status_code == 200:
        data = json.loads(response.text)
        if data:
            return data[cipher]['security']
        else:
            return ''
    else:
        return ''

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
                security_level = get_security_level(cipher)
                if security_level in ['weak', 'insecure']:
                    print(f"{line}\t\033[31m{security_level}\033[0m")
                elif security_level in ['secure', 'recommended']:
                    print(f"{line}\t\033[32m{security_level}\033[0m")
                else:
                    print(f"{line}\t{security_level}")
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
    parser = argparse.ArgumentParser(description='A script to assess the security level of SSL/TLS ciphers used by a target system.')
    parser.add_argument('target', help='The target system (ip:port)')

    args = parser.parse_args()

    if not args.target:
        parser.print_help(sys.stderr)
        sys.exit(1)
    # Check for updates
    check_for_updates(testssl_path)

    # Run testssl.sh
    run_testssl(args.target, testssl_path)
