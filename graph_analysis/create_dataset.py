import json
import argparse
import logging
from pathlib import Path
from packaging.version import Version

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def load_json_file(filepath):
    """Load a JSON file and handle errors gracefully."""
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        logging.error(f"JSON decoding error in {filepath}: {e}")
    except FileNotFoundError as e:
        logging.error(f"File not found: {filepath}: {e}")
    return None

def get_latest_version_key(package_data):
    """Get the latest version key from the package data."""
    latest_version_key = max(
        (version for version in package_data if is_valid_version(version)),
        key=Version,
        default=''
    )
    if latest_version_key:
        logging.debug(f"Latest version for package found: {latest_version_key}")
    else:
        logging.warning("No valid version found for package.")
    return latest_version_key

def is_valid_version(version):
    """Check if a version string can be parsed as a valid Version."""
    try:
        Version(version)
        return True
    except:
        logging.warning(f"Invalid version format encountered: {version}")
        return False

def count_unique_vulnerabilities(packages_data):
    """Count unique vulnerabilities across all versions of a package."""
    vulnerabilities = {
        vul_data['id']
        for version_data in packages_data.values()
        for vul_data in version_data.get('vulnerabilities', [])
    }
    logging.info(f"Unique vulnerabilities count: {len(vulnerabilities)}")
    return len(vulnerabilities)

def process_package(package_path, output_file, is_first):
    """Process a single package by linking it with CVEs and writing it to the output file."""
    packages_data = load_json_file(package_path)
    if not packages_data:
        logging.warning(f"Skipping package {package_path} due to loading error.")
        return is_first

    latest_version_key = get_latest_version_key(packages_data)
    if not latest_version_key or latest_version_key not in packages_data:
        logging.warning(f"No valid latest version found for package {package_path}. Skipping.")
        return is_first

    package_data = packages_data[latest_version_key]
    package_info = package_data.get('info', {})
    package_name = package_info.get('name')
    if not package_name:
        logging.warning(f"Package name missing in {package_path}. Skipping.")
        return is_first

    linked_data = {
        'name': package_name,
        'last_serial': package_data.get('last_serial'),
        'version': package_info.get('version'),
        'require_python': package_info.get('requires_python'),
        'historically_num_of_vulnerabilities': count_unique_vulnerabilities(packages_data),
        'require_dist': package_info.get('requires_dist', []),
        'package_vulnerabilities': package_data.get('vulnerabilities', []),
    }

    if not is_first:
        output_file.write(",\n")  # Add a comma before each JSON object
    json.dump(linked_data, output_file, indent=2)
    logging.info(f"Processed package: {package_name} (latest version: {latest_version_key})")
    return False  # Indicate that the first package has been processed

def process_packages_and_write(data_directory, output_path):
    """Process each package and write output incrementally to a JSON file."""
    package_dir = Path(data_directory)

    try:
        with open(output_path, 'w') as output_file:
            output_file.write("[\n")  # Start JSON array

            is_first = True
            for package_path in package_dir.glob('**/*.json'):
                if package_path.is_file() and  not package_path.match('release_data/serials.json'):
                    is_first = process_package(package_path, output_file, is_first)
                    logging.debug(f'Writing package {package_path}')
                    
            output_file.write("\n]")  # End JSON array
        logging.info(f"Data successfully written to {output_path}")
    except IOError as e:
        logging.error(f"Failed to write data to {output_path}: {e}")

def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Link CVEs with package metadata and save to a JSON file.")
    parser.add_argument('-d', '--data-directory', type=str, required=True, help='Path to the data directory')
    parser.add_argument('-o', '--output', type=str, required=True, help='Path to save the output JSON file.')
    return parser.parse_args()

def main():
    """Main function to process and save package metadata with linked CVEs."""
    args = parse_arguments()
    process_packages_and_write(args.data_directory, args.output)

if __name__ == "__main__":
    main()
