import networkx as nx
from typing import Dict
import pandas as pd
from metrics.abstract_metrics import GraphMetrics

class ComputeNumOfReachablePkgs(GraphMetrics):
    def __call__(self, graph: nx.Graph) -> dict[str, int]:
        num_of_reachable_pkgs = {}
        memo = {}

        def count_vulnerable_deps(node):
            if node in memo:
                return memo[node]

            visited = set()
            stack = [node]

            while stack:
                current = stack.pop()
                if current not in visited:
                    visited.add(current)
                    for neighbor in graph.successors(current):
                        if neighbor not in visited:
                            stack.append(neighbor)

            memo[node] = len(visited) - 1  # Exclude the starting node itself
            return memo[node]

        # Iterate through each node in the graph
        for node in graph.nodes:
            num_of_reachable_pkgs[node] = count_vulnerable_deps(node)

        return num_of_reachable_pkgs
   
    def todict(self, graph: nx.Graph) -> Dict[str, float]:
        num_of_reachable_pkgs = ComputeNumOfReachablePkgs()(graph)
        return {'num_of_reachable_packages': num_of_reachable_pkgs}

    def to_dataframe(self, graph: nx.Graph):
        num_of_reachable_pkgs = self.__call__(graph)
        return pd.dataframe({
            'Node': num_of_reachable_pkgs.keys(),
            'Num_of_reachable_packages': num_of_reachable_pkgs.values()
        })
    
    def print(self, graph: nx.Graph):
        num_of_reachable_pkgs = ComputeNumOfReachablePkgs()(graph)
        print("Num of reachable packages of each package")
        for pkg, num in num_of_reachable_pkgs.items():
            print(f'    Package: {pkg} ; Num of reachable packages: {num}')    