import os
import hashlib
import json

HASH_TABLE_FILE = "hash_table.json"


def hash_file(filepath):
    """
    Calculates and returns the SHA-256 hash of a file.
    """
    sha256 = hashlib.sha256()

    try:
        with open(filepath, "rb") as file:
            while True:
                chunk = file.read(4096)
                if not chunk:
                    break
                sha256.update(chunk)
        return sha256.hexdigest()
    except IOError:
        print(f"Error reading file: {filepath}")
        return None


def traverse_directory(directory):
    """
    Traverses a directory and returns a dictionary:
    {hash_value: file_path}
    """
    hash_map = {}

    for root, _, files in os.walk(directory):
        for filename in files:
            filepath = os.path.join(root, filename)
            file_hash = hash_file(filepath)

            if file_hash:
                hash_map[file_hash] = filepath

    return hash_map


def generate_table(directory):
    """
    Generates a hash table and saves it as a JSON file.
    """
    hash_table = traverse_directory(directory)

    with open(HASH_TABLE_FILE, "w") as json_file:
        json.dump(hash_table, json_file, indent=4)

    print("\nHash table generated successfully.")
    print(f"Saved as: {HASH_TABLE_FILE}\n")


def validate_hash(directory):
    """
    Validates files against the stored hash table.
    Detects valid, modified, new, deleted, and renamed files.
    """
    if not os.path.exists(HASH_TABLE_FILE):
        print("No hash table found. Please generate one first.\n")
        return

    with open(HASH_TABLE_FILE, "r") as json_file:
        stored_hashes = json.load(json_file)

    current_hashes = traverse_directory(directory)

    stored_hash_set = set(stored_hashes.keys())
    current_hash_set = set(current_hashes.keys())

    stored_paths = set(stored_hashes.values())
    current_paths = set(current_hashes.values())

    print("\n--- Hash Verification Results ---\n")

    # Check current files
    for current_hash, current_path in current_hashes.items():
        if current_hash in stored_hashes:
            old_path = stored_hashes[current_hash]

            if old_path != current_path:
                print("File name change detected:")
                print(f"  {old_path} -> {current_path}")
                stored_hashes[current_hash] = current_path
            else:
                print(f"{current_path} : Hash is VALID")
        else:
            if current_path in stored_paths:
                print(f"{current_path} : Hash is INVALID (file modified)")
            else:
                print(f"New file Added: {current_path}")

    # Check for deleted files
    for old_hash, old_path in stored_hashes.items():
        if old_path not in current_paths:
            print(f"File deleted: {old_path}")

    # Save updated hash table (for renamed files)
    with open(HASH_TABLE_FILE, "w") as json_file:
        json.dump(stored_hashes, json_file, indent=4)

    print("\nHash verification complete.\n")


def main():
    """
    Main program logic and user menu.
    """
    print("==== Hashing Program ====")
    print("1. Generate new hash table")
    print("2. Verify hashes")

    choice = input("\nEnter your choice (1 or 2): ").strip()

    if choice not in {"1", "2"}:
        print("Invalid selection. Exiting.")
        return

    directory = input("Enter directory path: ").strip()

    if not os.path.isdir(directory):
        print("Invalid directory path.")
        return

    if choice == "1":
        generate_table(directory)
    else:
        validate_hash(directory)


if __name__ == "__main__":
    main()
