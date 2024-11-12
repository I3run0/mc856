import networkx as nx
from typing import Dict
import pandas as pd
from metrics.abstract_metrics import GraphMetrics


class ComputeVulPackagesSucessor(GraphMetrics):
    def __call__(self, graph: nx.Graph) -> dict[str, int]:
        """Compute the vulnerable packages sucessors length of the graph."""
        vul_pkg_sucessor = {}

        def count_vulnerable_deps(node, visited):
            if node in visited:
                return False

            visited.add(node)

            for neighbor in graph.successors(node):
                count_vulnerable_deps(neighbor, visited)

        # Iterate through each node in the graph
        for node in graph.nodes:
            if graph.nodes[node]['is_vulnerable']:
                visited = set()
                count_vulnerable_deps(node, visited)
                visited.remove(node)
                vul_pkg_sucessor[node] = visited

        return vul_pkg_sucessor
   
    def todict(self, graph: nx.Graph) -> Dict[str, float]:
        vul_pkg_sucessor = ComputeVulPackagesSucessor()(graph)
        return vul_pkg_sucessor

    def to_dataframe(self, graph: nx.graph):
        vul_pkg_sucessor = self.__call__(graph)

        vul_ids = [graph.nodes[node]['vulnerabilities'] for node in vul_pkg_sucessor]
        num_of_sucessor = [len(node_list) for node_list in vul_pkg_sucessor.values()]

        return pd.DataFrame({
            'Node': vul_pkg_sucessor.keys(),
            'Vulnerabilities_ids': vul_ids,
            'Successors': vul_pkg_sucessor.values(),
            'Reached_packages': num_of_sucessor
        })
    
    def print(self, graph: nx.Graph):
        vul_pkg_sucessor = ComputeVulPackagesSucessor()(graph)
        print("Vulnerable packages sucessor")
        for pkg, sucessor_list in vul_pkg_sucessor.items():
            print(f'    Package {sucessor_list}')    