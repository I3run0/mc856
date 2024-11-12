import networkx as nx
from typing import Dict, List
import pandas as pd
from metrics.abstract_metrics import GraphMetrics


class ComputePctgOftheNetworkReached(GraphMetrics):
    def __call__(self, graph: nx.Graph, subset: list) -> dict[str, int]:
        visited = set()

        def bfs(node):
            if node in visited:
                return

            visited.add(node)

            for neighbor in graph.successors(node):
                bfs(neighbor)

        # Iterate through each node in the subset
        for node in subset:
            bfs(node)

        return len(visited) / graph.number_of_nodes()
   
    def todict(self, graph: nx.Graph, subset: list) -> Dict[str, float]:
        pct_of_network_reached = ComputePctgOftheNetworkReached()(graph, subset)
        return {
            'percentage_of_network_reached': {
                'subset': subset,
                'percentage': pct_of_network_reached
            }
        }

    def to_dataframe(self, graph: nx.Graph, subset: list) -> pd.DataFrame:
        """Convert the percentage of network reached into a DataFrame."""
        pct_of_network_reached = ComputePctgOftheNetworkReached()(graph, subset)
        
        # Create a DataFrame
        return pd.DataFrame({
            'Subset': [subset],
            'Percentage_of_Network_Reached': [pct_of_network_reached]
        })

    def print(self, graph: nx.Graph, subset: list):
        pct_of_network_reached = ComputePctgOftheNetworkReached()(graph, subset)
        print("Percentage of network reached by a subset")
        print(f'    Subset: {subset}; Percentage: {pct_of_network_reached}')    