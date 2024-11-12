from metrics.abstract_metrics import GraphMetrics
import networkx as nx
from typing import Dict

class ComputeClusteringCoefficient(GraphMetrics):
    def __call__(self, graph: nx.Graph) -> float:
        """Compute the average clustering coefficient of the graph."""
        avg_clustering = nx.average_clustering(graph)
        return avg_clustering

    def todict(self, graph: nx.Graph) -> Dict[str, float]:
        avg_clustering = ComputeClusteringCoefficient()(graph)
        return {
            'average_clustering_coefficient': avg_clustering,
        }

    def print(self, graph: nx.Graph):
        avg_clustering = ComputeClusteringCoefficient()(graph)
        print(f"Average Clustering Coefficient: {avg_clustering}")
