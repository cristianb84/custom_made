import argparse
import json
import re

def extract_unique_parameters(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()

        unique_keys = set()

        # Try to parse the whole file as JSON (Postman collection etc.)
        try:
            parsed = json.loads(content)
            unique_keys.update(extract_individual_keys(parsed))
        except json.JSONDecodeError:
            pass

        # Fallback: extract brace-based JSON fragments
        json_fragments = extract_json_fragments(content)
        for fragment in json_fragments:
            try:
                data = json.loads(fragment)
                unique_keys.update(extract_individual_keys(data))
            except json.JSONDecodeError:
                pass

        # Extract query/form/cookie parameter keys
        unique_keys.update(extract_kv_pairs(content))

        # Print sorted unique keys
        for key in sorted(unique_keys):
            print(key)

    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def extract_json_fragments(content):
    """
    Extract JSON objects or arrays from content using brace/bracket matching.
    """
    json_fragments = []
    stack = []
    current_fragment = []
    open_chars = {'{': '}', '[': ']'}
    close_chars = {'}': '{', ']': '['}

    for char in content:
        if char in open_chars:
            if not stack:
                current_fragment = []
            stack.append(char)
            current_fragment.append(char)
        elif char in close_chars:
            if stack and stack[-1] == close_chars[char]:
                stack.pop()
                current_fragment.append(char)
                if not stack:
                    fragment = ''.join(current_fragment)
                    json_fragments.append(fragment)
            elif stack:
                stack.pop()
        elif stack:
            current_fragment.append(char)

    return json_fragments

def extract_individual_keys(json_obj):
    """
    Recursively extract all individual keys from a JSON object.
    Also attempts to parse JSON strings (e.g. Postman raw bodies).
    """
    keys = set()
    if isinstance(json_obj, dict):
        for key, value in json_obj.items():
            keys.add(key)
            keys.update(extract_individual_keys(value))
    elif isinstance(json_obj, list):
        for item in json_obj:
            keys.update(extract_individual_keys(item))
    elif isinstance(json_obj, str):
        try:
            parsed = json.loads(json_obj)
            keys.update(extract_individual_keys(parsed))
        except (json.JSONDecodeError, TypeError):
            pass
    return keys

def extract_kv_pairs(content):
    """
    Extract parameter keys from query strings, form data, cookies, headers, and key-value like content.
    """
    pattern = re.compile(r'(?<!\w)([\w\[\]\.]+)(?==)')
    return set(pattern.findall(content))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract unique JSON and query parameter names from a file.")
    parser.add_argument("file", help="Path to the file to scan for parameters.")
    args = parser.parse_args()

    extract_unique_parameters(args.file)
