import os
import subprocess
import argparse

def get_current_version(repo_path):
    try:
        result = subprocess.run(["git", "describe", "--tags"], cwd=repo_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            return result.stdout.strip()
        else:
            return "Unknown"
    except Exception as e:
        print(f"Error fetching version: {str(e)}")
        return "Unknown"

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
            # Check for setup indicators
            setup_indicators = ['setup.py', 'setup.cfg', 'build']
            for root, dirs, files in os.walk(repo_path):
                if any(indicator in files + dirs for indicator in setup_indicators):
                    return "Repository updated successfully. Additional setup may be required."
            return "Repository updated successfully."
        else:
            return "Unrecognized status. Manual check recommended."
    except Exception as e:
        print(f"Error during pull: {str(e)}")
        return None

def is_git_repo(path):
    git_folder = os.path.join(path, ".git")
    return os.path.isdir(git_folder)

def check_repositories(root_path):
    summary = []
    for subdir, _, _ in os.walk(root_path):
        if is_git_repo(subdir):
            print(f"\nChecking repository: {subdir}")
            current_version = get_current_version(subdir)
            print(f"Current Version: {current_version}")
            update_status = git_pull(subdir)
            print(f"Update Status: {update_status}")
            summary.append((subdir, current_version, update_status))
    return summary

def display_summary(summary):
    print("\n\nSummary:")
    print(f"{'Repository':<60} {'Status':<20} {'Update Status':<50}")
    print("-" * 130)
    
    update_counts = {"Already up to date.": 0, "Repository updated successfully.": 0, "Error": 0}
    
    for repo, version, status in summary:
        short_status = "Not updated" if "Error" in status else status
        print(f"{repo:<60} {version:<20} {short_status:<50}")
        
        if status == "Already up to date.":
            update_counts["Already up to date."] += 1
        elif status == "Repository updated successfully.":
            update_counts["Repository updated successfully."] += 1
        else:
            update_counts["Error"] += 1
    
    print("\nTotal repositories identified: ", len(summary))
    print("Total repositories already up to date: ", update_counts["Already up to date."])
    print("Total repositories updated successfully: ", update_counts["Repository updated successfully."])
    print("Total repositories not updated due to errors: ", update_counts["Error"])

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='A script to check and update GitHub repositories recursively from a given root path.')
    parser.add_argument('root_path', help='The root path to check for repositories')

    args = parser.parse_args()

    if not args.root_path:
        parser.print_help()
        exit(1)

    summary = check_repositories(args.root_path)
    display_summary(summary)
