import networkx as nx
from typing import Dict

from metrics.abstract_metrics import GraphMetrics


class ComputePackagesReachedByVuln(GraphMetrics):
    def __call__(self, graph: nx.Graph) -> float:
        # Lists to store packages with and without vulnerable dependencies
        packages_with_vulnerable_deps = []
        packages_without_vulnerable_deps = []

        # Helper function to perform DFS to detect vulnerability in the dependency path
        def has_vulnerable_dependency(node, visited):
            if node in visited:
                return False

            if graph.nodes[node]['is_vulnerable']:
                return True

            visited.add(node)

            # Traverse through 'depends_on' edges only
            for neighbor in graph.successors(node):
                if graph[node][neighbor].get("relation") == "depends":
                    if has_vulnerable_dependency(neighbor, visited):
                        return True
            return False

        # Iterate through each node in the graph
        for node in graph.nodes:
            visited = set()  # Reset visited nodes for each new node search
            if has_vulnerable_dependency(node, visited):
                packages_with_vulnerable_deps.append(node)
            else:
                packages_without_vulnerable_deps.append(node)

        return packages_with_vulnerable_deps, packages_without_vulnerable_deps,\
              len(packages_with_vulnerable_deps), len(packages_without_vulnerable_deps)

    def todict(self, graph: nx.Graph) -> Dict[str, float]:
        vulnerable, non_vulnerable, nv, nn = ComputePackagesReachedByVuln()(graph)
        return {
            'number_of_packages_reached_by_vulnerable': nv,
            'number_of_packages_non_reached_by_vulnerable': nv,
            'packages_reached_vulnerable': vulnerable,
            'packages_non_reached_vulnerable': non_vulnerable
        }

    def print(self, graph: nx.Graph):
        vulnerable, non_vulnerable, nv, nnv = ComputePackagesReachedByVuln()(graph)
        print(f"Number of packages reached by vulnerabilities: {nv}")
        print(f"Number of packages non reached by vulnerabilities: {nnv}")
        print("Vulnerable packages")
        for i in vulnerable:
            print(f'    Package name: {i}')    
        print("Non Vulnerable packages")
        for i in non_vulnerable:
            print(f'    Package name: {i}')
