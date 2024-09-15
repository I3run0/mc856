import json
import os
import requests
import argparse
import zipfile
import zstandard as zstd
import io
import re
import shutil

CVE_DIR = 'CVE'
PACKAGES_PATH = 'PACKAGES/pypicache.json'
PYPI_URL = 'https://pypi.org/pypi/{package}/json'
OSV_CVE_URL = 'https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip'
REPOLOGY_PYPI_URL = 'https://pypicache.repology.org/pypicache.json.zst'


def download_and_extract_cve_data():
    """Download and extract the CVEs from the all.zip file."""
    print("Downloading CVE data from:", OSV_CVE_URL)
    try:
        response = requests.get(OSV_CVE_URL)
        response.raise_for_status()

        # Extract the zip file in memory
        with zipfile.ZipFile(io.BytesIO(response.content)) as z:
            z.extractall(CVE_DIR)
        print(f"Extracted CVEs to {CVE_DIR}")
    except requests.exceptions.RequestException as e:
        print(f"Failed to download CVE data: {e}")


def download_repology_package_data():
    """Download the package metadata from the Repology PyPi cache."""
    print("Downloading package metadata from Repology:", REPOLOGY_PYPI_URL)
    try:
        response = requests.get(REPOLOGY_PYPI_URL)
        response.raise_for_status()

        # Decompress the .zst file
        dctx = zstd.ZstdDecompressor()
        with dctx.stream_reader(io.BytesIO(response.content)) as reader:
            with open(PACKAGES_PATH, 'wb') as f:
                shutil.copyfileobj(reader, f)
        print(f"Saved package metadata to {PACKAGES_PATH}")
    except requests.exceptions.RequestException as e:
        print(f"Failed to download package metadata: {e}")
    except zstd.ZstdError as e:
        print(f"Failed to decompress .zst file: {e}")

def load_json_file(filepath):
    """Helper function to load a JSON file and handle errors."""
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"Error loading {filepath}: {e}")
        return None


def fetch_package_from_pypi(package_name):
    """Fetch package metadata from PyPI."""
    try:
        response = requests.get(PYPI_URL.format(package=package_name))
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Failed to fetch {package_name} from PyPI: {e}")
        return None

def ensure_dependencies(packages, package_data, package_name):
    """Ensure all dependencies (requires_dist) are included in the dataset."""
    dependencies = package_data['info'].get('requires_dist', [])
    
    if not dependencies:
        return  # No dependencies to check

    # Regex to capture package name (ignores version constraints and extras)
    package_name_regex = re.compile(r'^[A-Za-z0-9_\-\.]+')

    for dep in dependencies:
        # Use regex to extract package name
        match = package_name_regex.match(dep.split()[0])
        if match:
            dep_name = match.group(0)
            if dep_name not in {pkg['info']['name'] for pkg in packages}:  # Check if already in the dataset
                print(f"Dependency {dep_name} not found. Fetching from PyPI...")
                dep_package_data = fetch_package_from_pypi(dep_name)
                if dep_package_data:
                    packages.append(dep_package_data)


def get_cve():
    """Parses CVE data, linking them with aliases and specific details."""
    cves_json = {}
    for root, _, files in os.walk(CVE_DIR):
        for file in files:
            if file.endswith('.json') and file.startswith('PYSEC'):
                js = load_json_file(os.path.join(root, file))
                if not js:
                    continue  # Skip if the file could not be loaded

                # Try to fetch additional information from aliases
                database_specific = None
                for alias in js.get('aliases', []):
                    if 'GHSA' in alias:
                        alias_file = f'{CVE_DIR}/{alias}.json'
                        alias_data = load_json_file(alias_file)
                        if alias_data:
                            database_specific = alias_data.get('database_specific')

                js['database_specific'] = database_specific

                for affected in js.get('affected', []):
                    package_name = affected['package']['name']
                    cves_json.setdefault(package_name, []).append(js)

    return cves_json


def link_cve_with_packages():
    """Links CVEs with package metadata and ensures all dependencies are included."""
    cves = get_cve()
    packages_formated = []

    packages = load_json_file(PACKAGES_PATH)
    if not packages:
        return []  # Return empty list if the package file could not be loaded

    for package in packages:
        try:
            package_name = package['info']['name']
            p = {
                'name': package_name,
                'last_serial': package['last_serial'],
                'require_dist': package['info'].get('requires_dist', []),
                'package_vulnerabilities': package.get('vulnerabilities', []),
                'advisor_vulnerabilities': cves.get(package_name, [])
            }

            # Ensure all dependencies are included in the dataset
            #ensure_dependencies(packages, package, package_name)

            packages_formated.append(p)
        except KeyError as e:
            print(f"Missing key in package data: {e}")
            continue

    return packages_formated


def write_to_json_file(data, output_path):
    """Writes the formatted data to a JSON file at the user-provided path."""
    try:
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"Data successfully written to {output_path}")
    except IOError as e:
        print(f"Failed to write data to {output_path}: {e}")


def parse_arguments():
    """Parse command-line arguments using argparse."""
    parser = argparse.ArgumentParser(description="Link CVEs with package metadata and save it to a JSON file.")
    parser.add_argument(
        '-o', '--output', 
        type=str, 
        required=True, 
        help='Path to save the output JSON file.'
    )
    return parser.parse_args()


def main():
    """Main function to process and save the package metadata with linked CVEs."""
    args = parse_arguments()
    output_path = args.output

    # Download CVE data and package data
    download_and_extract_cve_data()
    download_repology_package_data()

    package_data = link_cve_with_packages()

    # Write the formatted data to the JSON file
    write_to_json_file(package_data, output_path)


if __name__ == "__main__":
    main()
