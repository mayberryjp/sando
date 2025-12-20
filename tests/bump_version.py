#!/usr/bin/env python3
import os
import re


def increment_version(version_str):
    """Increment the patch version number in a version string like 'v0.2.7'"""
    # Remove the 'v' prefix for parsing
    match = re.match(r"v(\d+)\.(\d+)\.(\d+)", version_str)
    if not match:
        raise ValueError(f"Invalid version format: {version_str}")

    major, minor, patch = map(int, match.groups())
    new_patch = patch + 1

    # Return the full version string with 'v' prefix
    return f"v{major}.{minor}.{new_patch}"


def update_version_in_file(file_path):
    """Update the version in the const.py file"""
    # Read the entire file
    with open(file_path, "r") as file:
        lines = file.readlines()

    # Find and update the VERSION line
    for i, line in enumerate(lines):
        if line.startswith("VERSION="):
            # Extract the current version string
            match = re.search(r'VERSION="(v\d+\.\d+\.\d+)"', line)
            if match:
                current_version = match.group(1)
                new_version = increment_version(current_version)
                # Replace just the version part, maintaining the exact formatting
                lines[i] = line.replace(current_version, new_version)
                print(f"Updated version from {current_version} to {new_version}")
                break
    else:
        print("VERSION line not found in file")
        return False

    # Write the modified content back to the file
    with open(file_path, "w") as file:
        file.writelines(lines)

    return True


if __name__ == "__main__":
    const_file = "src/const.py"

    # Ensure the file exists
    if not os.path.exists(const_file):
        print(f"Error: File {const_file} not found")
        exit(1)

    # Update the version
    if update_version_in_file(const_file):
        print(f"Successfully updated version in {const_file}")
    else:
        print(f"Failed to update version in {const_file}")
