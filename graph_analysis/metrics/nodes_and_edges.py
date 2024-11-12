from metrics.abstract_metrics import GraphMetrics
import networkx as nx
from typing import Tuple, Dict, List, Optional
import sys

class ComputeNodesAndEdges(GraphMetrics):
    def __call__(self, graph: nx.Graph) -> Tuple[int, int]:
        """Compute the clustering coefficient for each node."""
        num_nodes = graph.number_of_nodes()
        num_edges = graph.number_of_edges()
        return num_nodes, num_edges

    def todict(self, graph: nx.Graph):
        num_nodes, num_edges = ComputeNodesAndEdges()(graph)
        return {
                'num_nodes': num_nodes,
                'num_edges': num_edges,
                }

    def print(self, graph: nx.graph):
        num_nodes, num_edges = ComputeNodesAndEdges()(graph)
        print(f"Number of nodes: {num_nodes}")
        print(f"Number of edges: {num_edges}")


class ComputeDensity(GraphMetrics):
    def __call__(self, graph: nx.Graph) -> float:
        """Compute the density of the graph."""
        num_edges = graph.number_of_edges()
        num_nodes = graph.number_of_nodes()
        max_edges = num_nodes * (num_nodes - 1) / 2
        density = num_edges / max_edges if max_edges > 0 else 0
        return density

    def todict(self, graph: nx.Graph) -> Dict[str, float]:
        density = ComputeDensity()(graph)
        return {
            'density': density,
        }

    def print(self, graph: nx.Graph):
        density = ComputeDensity()(graph)
        print(f"Density: {density}")
