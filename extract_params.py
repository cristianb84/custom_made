import argparse
import json
import re

def extract_unique_parameters(file_path):
    try:
        # Read the entire file
        with open(file_path, 'r') as file:
            content = file.read()

        # Attempt to locate JSON fragments robustly
        json_fragments = extract_json_fragments(content)
        unique_keys = set()

        for fragment in json_fragments:
            try:
                # Parse the JSON fragment
                data = json.loads(fragment)

                # Add the keys to the unique_keys set
                unique_keys.update(extract_individual_keys(data))
            except json.JSONDecodeError:
                # Skip invalid JSON fragments
                pass

        # Sort and print the unique keys
        for key in sorted(unique_keys):
            print(key)

    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def extract_json_fragments(content):
    """
    Extract potential JSON fragments from the content.
    """
    json_fragments = []
    braces_stack = []
    current_fragment = []

    for char in content:
        if char == '{':
            if not braces_stack:
                current_fragment = []
            braces_stack.append(char)
            current_fragment.append(char)
        elif char == '}':
            if braces_stack:
                braces_stack.pop()
                current_fragment.append(char)
                if not braces_stack:
                    json_fragments.append(''.join(current_fragment))
        elif braces_stack:
            current_fragment.append(char)

    return json_fragments

def extract_individual_keys(json_obj):
    """
    Recursively extract all individual keys from a JSON object.
    """
    keys = set()
    if isinstance(json_obj, dict):
        for key, value in json_obj.items():
            keys.add(key)
            keys.update(extract_individual_keys(value))
    elif isinstance(json_obj, list):
        for item in json_obj:
            keys.update(extract_individual_keys(item))
    return keys

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract unique JSON parameter names from a file.")
    parser.add_argument("file", help="Path to the file containing JSON objects.")
    args = parser.parse_args()

    extract_unique_parameters(args.file)
