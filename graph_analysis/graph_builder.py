import networkx as nx
import re
import logging
import json
from packaging.specifiers import SpecifierSet
from packaging.version import Version

# Configure logging
logging.basicConfig(level=logging.ERROR, format='%(levelname)s: %(message)s')

def is_compatible_versions(version_req1, version_req2):
    """Check if there is a compatible version that satisfies both version requirements."""
    # If no version requirement is specified, assume the latest version is compatible.
    if not version_req1 or not version_req2:
        logging.debug(f"No version requirement for one or both: {version_req1}, {version_req2}")
        return True
    try:
        specifier1 = SpecifierSet(version_req1)
        specifier2 = SpecifierSet(version_req2)    
        # Find a version in specifier1 that could satisfy specifier2 by checking for intersection
        compatible = bool(specifier1 & specifier2)
        logging.debug(f"Version requirements {version_req1} and {version_req2} compatible: {compatible}")
        return compatible
    except Exception as e:
        logging.warning(f"Error checking compatibility of {version_req1} and {version_req2}: {e}")
        return False

def parse_dependency(depname):
    """Parse a dependency string to extract package name and version constraints."""
    match = re.match(r"([^ \[\(\)><=~;]+)(.*)", depname)
    if match:
        package_name = match.group(1)
        version_info = match.group(2).strip()
        logging.debug(f"Parsed dependency {depname}: name={package_name}, version={version_info}")
        return package_name, version_info
    logging.warning(f"Failed to parse dependency: {depname}")
    return None, None

def get_vulnerabilities(package_name, vulnerability_dict):
    """Retrieve vulnerabilities for a package from the vulnerability dictionary."""
    if package_name in vulnerability_dict and vulnerability_dict[package_name]:
        vulnerabilities = [vul['id'] for vul in vulnerability_dict.get(package_name, [])]
        logging.debug(f"Vulnerabilities for {package_name}: {vulnerabilities}")
        return vulnerabilities
    logging.debug(f"No vulnerabilities found for {package_name}")
    return ''

def add_package_node(graph, pkg_name, is_vulnerable, vulnerabilities):
    """Add a package node to the graph with vulnerability information."""
    graph.add_node(pkg_name, type='project', is_vulnerable=is_vulnerable, vulnerabilities=vulnerabilities)
    logging.info(f"Added node for package {pkg_name} with vulnerabilities: {vulnerabilities}")

def add_dependency_edge(graph, pkg_name, dep_name, dep_python_requirement):
    """Add a dependency edge between two packages in the graph."""
    try:
        graph.add_edge(
            pkg_name, dep_name,
            relation='depends',
            python_version=dep_python_requirement or 'Any'
        )
        logging.info(f"Added edge from {pkg_name} to {dep_name} with Python requirement: {dep_python_requirement}")
    except Exception as e:
        logging.error(f"Error adding edge {pkg_name} -> {dep_name}: {e}")

def process_package_dependencies(package, data, vulnerability_dict, graph):
    """Process dependencies of a package and add nodes and edges to the graph."""
    pkg_name = package['name'].lower()
    pkg_python_version = package.get('require_python')
    node_vulnerabilities = get_vulnerabilities(pkg_name, vulnerability_dict)

    # Add package node with vulnerability information
    add_package_node(graph, pkg_name, bool(node_vulnerabilities), node_vulnerabilities)

    dependencies = package.get('require_dist', [])
    if not dependencies:
        logging.debug(f"No dependencies found for {pkg_name}")
        return

    for dependency in dependencies:
        dep_name, version_constraints = parse_dependency(dependency.lower())
        if not dep_name or version_constraints != '':
            continue

        # Check for Python version compatibility before adding the edge
        dep_python_requirement = data.get(dep_name, {}).get('require_python')
        if is_compatible_versions(pkg_python_version, dep_python_requirement):
            dep_vulnerabilities = get_vulnerabilities(dep_name, vulnerability_dict)
            is_vulnerable_dep = bool(dep_vulnerabilities)

            # Add dependency node if not already present
            if dep_name not in graph:
                add_package_node(graph, dep_name, is_vulnerable_dep, dep_vulnerabilities)
            
            # Add dependency edge between the package and its dependency
            add_dependency_edge(graph, pkg_name, dep_name, dep_python_requirement)

def build_dependency_graph(data, vulnerability_dict):
    """Build a directed graph of package dependencies with vulnerability information."""
    graph = nx.DiGraph()
    for package in data.values():
        process_package_dependencies(package, data, vulnerability_dict, graph)
    logging.info("Dependency graph construction completed.")
    return graph

def build_dependency_graph_from_json(json_file):
    data = json.load(open(json_file))

    vulnerability_dict = {
        package['name'].lower(): [vul for vul in package.get('package_vulnerabilities', [])]
        for package in data
    }

    packages = {package['name']: package for package in data}
    return build_dependency_graph(packages, vulnerability_dict)

# Example of building the graph
# PDGraph = build_dependency_graph(data, vulnerability_dict)
