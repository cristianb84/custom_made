#!/usr/bin/env python3

import os
import shutil
import argparse

def create_folders(task_name):
    base_dir = os.path.expanduser('~/Desktop/Synack')
    task_dir = os.path.join(base_dir, task_name)

    folders = [
        task_dir,
        os.path.join(task_dir, 'nmap'),
        os.path.join(task_dir, 'Burp'),
        os.path.join(task_dir, 'ferox'),
        os.path.join(task_dir, 'writeup'),
	os.path.join(task_dir, 'Downloads'),
    ]

    for folder in folders:
        try:
            os.makedirs(folder, exist_ok=True)
            print(f"Successfully created {folder}")
        except Exception as e:
            print(f"Failed to create {folder}. Reason: {str(e)}")

def copy_template_file(task_name):
    source_file = os.path.expanduser('~/Documents/bb-template.ctb')
    dest_file = os.path.expanduser(f'~/Desktop/Synack/{task_name}/writeup/{task_name}.ctb')

    try:
        shutil.copy2(source_file, dest_file)
        print(f"Successfully copied to {dest_file}")
    except Exception as e:
        print(f"Failed to copy template file. Reason: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description="Initialize Bug Bounty Task Folders")
    parser.add_argument('-t', '--task', required=True, help="Task name")
    args = parser.parse_args()

    create_folders(args.task)
    copy_template_file(args.task)

if __name__ == "__main__":
    main()
