import subprocess
import os
import argparse

def get_latest_tag(repo_path):
    try:
        result = subprocess.run(["git", "describe", "--tags"], cwd=repo_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.stdout.strip()
    except Exception as e:
        print(f"Error getting tag: {str(e)}")
        return None

def git_pull(repo_path):
    try:
        result = subprocess.run(["git", "pull"], cwd=repo_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        all_output = result.stdout + result.stderr
        if "Already up to date." in all_output:
            return "Already up to date."
        elif "error:" in all_output:
            error_msg = all_output.split("error:")[1].strip()
            return f"Error during update: {error_msg}"
        elif "fatal:" in all_output:
            fatal_msg = all_output.split("fatal:")[1].strip()
            return f"Fatal error during update: {fatal_msg}"
        elif "Updating" in all_output or "Fast-forward" in all_output:
            return "Repository updated successfully."
        else:
            return "Unrecognized status. Manual check recommended."
    except Exception as e:
        print(f"Error during pull: {str(e)}")
        return None

def find_git_repos(path):
    for root, dirs, files in os.walk(path):
        if ".git" in dirs:
            yield root

def main(path):
    for repo in find_git_repos(path):
        print(f"\nChecking repository: {repo}")
        current_version = get_latest_tag(repo)
        print(f"Current Version: {current_version if current_version else 'Unknown'}")
        
        pull_result = git_pull(repo)
        print(f"Update Status: {pull_result}")
        
        new_version = get_latest_tag(repo)
        if current_version != new_version:
            print(f"Updated Version: {new_version if new_version else 'Unknown'}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Update Git repositories in a given path.')
    parser.add_argument('path', help='The path to check for repositories')

    args = parser.parse_args()
    
    if not os.path.exists(args.path):
        print("Provided path does not exist.")
    else:
        main(args.path)
