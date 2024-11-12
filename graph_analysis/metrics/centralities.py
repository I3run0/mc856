import networkx as nx
from metrics.abstract_metrics import GraphMetrics
from typing import Dict, Tuple

class DegreeCentrality(GraphMetrics):
    def __call__(self, graph: nx.Graph) -> Dict[int, float]:
        """Compute degree centrality for each node."""
        return nx.degree_centrality(graph)

    def todict(self, graph: nx.Graph) -> Dict[str, Dict[int, float]]:
        return {'degree_centrality': self.__call__(graph)}

    def print(self, graph: nx.Graph):
        centrality = self.__call__(graph)
        print("Degree Centrality:")
        for node, score in centrality.items():
            print(f"  Node {node}: {score:.4f}")

class BetweennessCentrality(GraphMetrics):
    def __call__(self, graph: nx.Graph) -> Dict[int, float]:
        """Compute betweenness centrality for each node."""
        return nx.betweenness_centrality(graph)

    def todict(self, graph: nx.Graph) -> Dict[str, Dict[int, float]]:
        return {'betweenness_centrality': self.__call__(graph)}

    def print(self, graph: nx.Graph):
        centrality = self.__call__(graph)
        print("Betweenness Centrality:")
        for node, score in centrality.items():
            print(f"  Node {node}: {score:.4f}")

class ClosenessCentrality(GraphMetrics):
    def __call__(self, graph: nx.Graph) -> Dict[int, float]:
        """Compute closeness centrality for each node."""
        return nx.closeness_centrality(graph)

    def todict(self, graph: nx.Graph) -> Dict[str, Dict[int, float]]:
        return {'closeness_centrality': self.__call__(graph)}

    def print(self, graph: nx.Graph):
        centrality = self.__call__(graph)
        print("Closeness Centrality:")
        for node, score in centrality.items():
            print(f"  Node {node}: {score:.4f}")

class EigenvectorCentrality(GraphMetrics):
    def __call__(self, graph: nx.Graph) -> Dict[int, float]:
        """Compute eigenvector centrality for each node."""
        try:
            return nx.eigenvector_centrality(graph)
        except nx.PowerIterationFailedConvergence:
            print("Eigenvector centrality computation did not converge.")
            return {}

    def todict(self, graph: nx.Graph) -> Dict[str, Dict[int, float]]:
        return {'eigenvector_centrality': self.__call__(graph)}

    def print(self, graph: nx.Graph):
        centrality = self.__call__(graph)
        print("Eigenvector Centrality:")
        for node, score in centrality.items():
            print(f"  Node {node}: {score:.4f}")
