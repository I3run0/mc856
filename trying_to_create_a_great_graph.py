import networkx as nx
import re
from packaging.specifiers import SpecifierSet
from packaging.version import Version
import json
import requirements
import ijson

import ijson

'''
def process_large_json(filename):
    package_dependencies = {}

    # Open the large JSON file
    with open(filename, 'r') as f:
        # Use ijson to read the JSON file iteratively
        for package in ijson.items(f, 'item'):
            name = package['name']
            versions_metadata = package['versions_metadata']

            # Initialize the package in the dependencies dictionary
            package_dependencies[name] = {}

            # Iterate through each version and its dependencies
            for version, metadata in versions_metadata.items():
                # Extract the required distributions
                require_dist = metadata.get('require_dist', [])
                package_dependencies[name][version] = require_dist

    return package_dependencies

# Example usage
filename = 'dataset/zero,.json'
dependencies = process_large_json(filename)

# Now you can access the dependencies of any package
for package, versions in dependencies.items():
    print(f"Package: {package}")
    for version, reqs in versions.items():
        print(f"  Version: {version}, Requires: {reqs}")



import networkx as nx

def create_dvgraph(package_data):
    # Initialize a directed graph
    dv_graph = nx.DiGraph()

    for package in package_data:
        name = package["name"]
        versions_metadata = package["versions_metadata"]

        for version, metadata in versions_metadata.items():
            # Add library and version nodes
            dv_graph.add_node(name, type='Lib')
            dv_graph.add_node(f"{name}=={version}", type='Ver')

            # Create the has relation
            dv_graph.add_edge(name, f"{name}=={version}", relation='has')

            # Add dependencies
            require_dist = metadata.get("require_dist", [])
            for dep in require_dist:
                dep_name, dep_version = dep.split(" (==")
                dep_version = dep_version[:-1]  # Remove trailing ")"
                dv_graph.add_node(dep_name, type='Lib')
                dv_graph.add_edge(f"{name}=={version}", dep_name, relation='depends')
                dv_graph.add_edge(dep_name, f"{dep_name}=={dep_version}", relation='libdeps')

            # Add version relationships (example: upper/lower)
            # Assuming you have logic to determine upper/lower versions, add them here.

            # Add vulnerabilities if any
            vulnerabilities = metadata.get("package_vulnerabilities", [])
            for vul in vulnerabilities:
                vul_node = f"Vul:{vul['id']}"  # Assuming vulnerabilities have an id
                dv_graph.add_node(vul_node, type='Vul')
                dv_graph.add_edge(vul_node, f"{name}=={version}", relation='affects')
                dv_graph.add_edge(vul_node, name, relation='libaffects')

    return dv_graph

# Example usage
package_data = [
    {
        "name": "c",
        "versions_metadata": {
            "0.0.1": {
                "require_dist": [],
                "package_vulnerabilities": []
            },
            "0.0.2": {
                "require_dist": ["cycler (==0.10.0)"],
                "package_vulnerabilities": [{"id": "CVE-1234"}]
            }
        }
    }
]

dv_graph = create_dvgraph(package_data)

# Example of querying the graph
for node in dv_graph.nodes(data=True):
    print(node)
'''

def process_large_json(filename):
    package_dependencies = {}

    # Open the large JSON file
    with open(filename, 'r') as f:
        # Use ijson to read the JSON file iteratively
        for package in ijson.items(f, 'item'):
            name = package['name']
            versions_metadata = package['versions_metadata']

            # Initialize the package in the dependencies dictionary
            package_dependencies[name] = {}

            # Iterate through each version and its dependencies
            for version, metadata in versions_metadata.items():
                # Extract the required distributions
                require_dist = metadata.get('require_dist', [])
                pkg_vulnerabilities = metadata.get('package_vulnerabilities', [])
                package_dependencies[name][version] = {}
                package_dependencies[name][version]['require_dist'] = require_dist
                package_dependencies[name][version]['package_vulnerabilities'] = [
                   vul['id'] for vul in pkg_vulnerabilities
                ]

    return package_dependencies


def extract_package_versions(requirements):
    package_versions = []
    # Regex pattern to match package name, extras, version constraints, and conditions
    pattern = r'([a-zA-Z0-9_\-\.]+)(\[[^\]]+\])?\s*(\([><=!~,\s*\.\d*]*\)|[><=!~,\s*\.\d*]*)?\s*(?:;\s*(.*))?'

    for requirement in requirements:
        match = re.match(pattern, requirement)
        if match:
            package_name = match.group(1)
            extras = match.group(2).strip("[]") if match.group(2) else None
            version_constraints = match.group(3).replace("(", "").replace(")", "").strip() if match.group(3) else None
            condition = match.group(4).strip() if match.group(4) else None
            
            package_versions.append({
                'package_name': package_name,
                'extras': extras,
                'version_constraints': version_constraints,
                'condition': condition
            })
    
    return package_versions

def get_default_version(pkg_version, version_constraint):
    if pkg_version == None:
        return version_constraint[-1]
    
    try:
        specifier_set = SpecifierSet(pkg_version)
        return list(specifier_set.filter(version_constraint))[-1]
    except:
        return None

def create_dv_graph(package_dependencies):
    dv_graph = nx.DiGraph()

    for name, versions in package_dependencies.items():
        dv_graph.add_node(name, type='Lib')

        for version, metadata in versions.items():
            # Create a node for the version
            dv_graph.add_node(f"{name}=={version}", type='Ver')

            # Define the inner-library relations
            dv_graph.add_edge(name, f"{name}=={version}", relation='has')

            # Placeholder for upper/lower versions (you need to implement the logic)
            # dv_graph.add_edge(f"{name}=={version}", f"{name}=={upper_version}", relation='upper')
            # dv_graph.add_edge(f"{name}=={version}", f"{name}=={lower_version}", relation='lower')

            # Extract dependencies and vulnerabilities
            require_dist = metadata.get('require_dist', [])
            pkg_vulnerabilities = metadata.get('package_vulnerabilities', [])

            # Add edges for dependencies
            if require_dist == None:
                continue

            for dep in require_dist:
                pkg_name, extras, versions_constraints, condition = extract_package_versions([dep])[0].values() # Adjust based on actual format
                dv_graph.add_edge(f"{name}=={version}", pkg_name, relation='depends')

                # Get the default version for the dependency
                try:
                    dep_version = list(package_dependencies[pkg_name.lower()].keys())
                except:
                    continue
                
                default_version = get_default_version(versions_constraints, dep_version)
            
                if default_version != None:
                    dv_graph.add_edge(f"{name}=={version}", f"{pkg_name}=={default_version}", relation='default')
            
            # Add edges for vulnerabilities
            for vul in pkg_vulnerabilities:
                dv_graph.add_node(vul, type='Vul')
                dv_graph.add_edge(vul, f"{name}=={version}", relation='affects')
                dv_graph.add_edge(vul, name, relation='libaffects')

    return dv_graph

# Example usage
filename = 'dataset/zero.json'
dependencies = process_large_json(filename)
dv_graph = create_dv_graph(dependencies)