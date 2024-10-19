import json
import os
import argparse
from pathlib import Path

CVE_DIR = 'CVE'
PYPI_JSON_DATA = './pypi-json-data/release_data/'


def load_json_file(filepath):
    """Load a JSON file with error handling."""
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"Error loading {filepath}: {e}")
        return None


def collect_cve_data():
    """Collect all CVE data and organize it by package name."""
    cves = {}
    for root, _, files in os.walk(CVE_DIR):
        for file in files:
            if file.endswith('.json') and file.startswith('PYSEC'):
                cve_data = load_json_file(os.path.join(root, file))
                if cve_data:
                    for affected in cve_data.get('affected', []):
                        package_info = affected.get('package', {})
                        package_name = package_info.get('name')
                        if package_name:
                            if package_name not in cves:
                                cves[package_name] = []
                            cves[package_name].append(cve_data)
    return cves


def process_package(package_path, cves, output_file, is_first):
    """Process a single package by linking it with CVEs and writing it to the output file."""
    package_data = list(load_json_file(package_path).items())[-1][1]

    if not package_data or 'info' not in package_data or 'name' not in package_data['info']:
        return is_first  # If the package is invalid, return the original is_first flag

    package_name = package_data['info'].get('name')
    if not package_name:
        return is_first  # Skip if the package doesn't have a valid name
    
    # Link CVEs with the package
    linked_data = {
        'name': package_name,
        'last_serial': package_data.get('last_serial', None),
        'require_dist': package_data['info'].get('requires_dist', []),
        'package_vulnerabilities': package_data.get('vulnerabilities', []),
        'advisor_vulnerabilities': cves.get(package_name, [])
    }
    
    # Write to file immediately
    if not is_first:
        output_file.write(",\n")  # Add a comma before the next JSON object
    json.dump(linked_data, output_file, indent=2)

    return False  # Indicate that this is no longer the first package


def process_packages_and_write(cves, output_path):
    """Process each package and write the output incrementally."""
    package_dir = Path(PYPI_JSON_DATA)

    try:
        with open(output_path, 'w') as output_file:
            output_file.write("[\n")  # Start the JSON array

            is_first = True  # Track if we are writing the first package
            for package_path in package_dir.glob('**/*.json'):
                if package_path.is_file():
                    is_first = process_package(package_path.as_posix(), cves, output_file, is_first)
                    print(f'Writing package {package_path}')
            output_file.write("\n]")  # End the JSON array
        print(f"Data successfully written to {output_path}")
    except IOError as e:
        print(f"Failed to write data to {output_path}: {e}")


def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Link CVEs with package metadata and save to a JSON file.")
    parser.add_argument('-o', '--output', type=str, required=True, help='Path to save the output JSON file.')
    return parser.parse_args()


def main():
    """Main function to process and save the package metadata with linked CVEs."""
    args = parse_arguments()
    output_path = args.output

    # Collect all CVE data
    cves = collect_cve_data()

    # Process each package and write the results to the output file incrementally
    process_packages_and_write(cves, output_path)


if __name__ == "__main__":
    main()
