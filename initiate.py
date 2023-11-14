#!/usr/bin/env python3

import os
import shutil
import argparse

def create_folders(base_dir, task_name):
    task_dir = os.path.join(base_dir, task_name)

    folders = [
        task_dir,
        os.path.join(task_dir, 'nmap'),
        os.path.join(task_dir, 'Burp'),
        os.path.join(task_dir, 'ferox'),
        os.path.join(task_dir, 'writeup'),
        os.path.join(task_dir, 'Downloads'),
	os.path.join(task_dir, 'sslscan'),
        os.path.join(task_dir, 'Screenshots'),
    ]

    for folder in folders:
        try:
            os.makedirs(folder, exist_ok=True)
            print(f"Successfully created {folder}")
        except Exception as e:
            print(f"Failed to create {folder}. Reason: {str(e)}")

def copy_template_file(base_dir, task_name):
    # Construct the path to bb-template.ctb relative to the script's location
    source_file = os.path.join(os.path.dirname(__file__), 'bb-template.ctb')
    dest_file = os.path.expanduser(os.path.join(base_dir, task_name, 'writeup', f'{task_name}.ctb'))

    try:
        shutil.copy2(source_file, dest_file)
        print(f"Successfully copied to {dest_file}")
    except Exception as e:
        print(f"Failed to copy template file. Reason: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description="Initialize Bug Bounty Task Folders")
    parser.add_argument('base_dir', help="Base directory where the task folder will be created")
    parser.add_argument('task_name', help="Task name")
    args = parser.parse_args()

    create_folders(os.path.expanduser(args.base_dir), args.task_name)
    copy_template_file(os.path.expanduser(args.base_dir), args.task_name)

if __name__ == "__main__":
    main()
