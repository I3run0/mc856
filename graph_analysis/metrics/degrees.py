import networkx as nx
import pandas as pd
from typing import Dict
from metrics.abstract_metrics import GraphMetrics

class ComputeInDegree(GraphMetrics):
    def __call__(self, graph: nx.DiGraph) -> dict[str, int]:
        # Compute in-degree of each node
        in_degrees = {node: in_deg for node, in_deg in graph.in_degree()}
        return in_degrees

    def todict(self, graph: nx.DiGraph) -> Dict[str, int]:
        in_degrees = self.__call__(graph)
        return {'in_degrees': in_degrees}

    def to_dataframe(self, graph: nx.DiGraph) -> pd.DataFrame:
        """Convert the in-degrees to a DataFrame."""
        in_degrees = self.__call__(graph)
        return pd.DataFrame(list(in_degrees.items()), columns=['Node', 'In-Degree'])

    def print(self, graph: nx.DiGraph):
        in_degrees = self.__call__(graph)
        print("In-degree of each node in the graph:")
        for node, in_degree in in_degrees.items():
            print(f'    Node: {node} ; In-Degree: {in_degree}')


class ComputeOutDegree(GraphMetrics):
    def __call__(self, graph: nx.DiGraph) -> dict[str, int]:
        # Compute out-degree of each node
        out_degrees = {node: out_deg for node, out_deg in graph.out_degree()}
        return out_degrees

    def todict(self, graph: nx.DiGraph) -> Dict[str, int]:
        out_degrees = self.__call__(graph)
        return {'out_degrees': out_degrees}

    def to_dataframe(self, graph: nx.DiGraph) -> pd.DataFrame:
        """Convert the out-degrees to a DataFrame."""
        out_degrees = self.__call__(graph)
        return pd.DataFrame(list(out_degrees.items()), columns=['Node', 'Out-Degree'])

    def print(self, graph: nx.DiGraph):
        out_degrees = self.__call__(graph)
        print("Out-degree of each node in the graph:")
        for node, out_degree in out_degrees.items():
            print(f'    Node: {node} ; Out-Degree: {out_degree}')


class ComputeAverageDegree(GraphMetrics):
    def __call__(self, graph: nx.Graph) -> float:
        """Compute the average degree of the graph."""
        total_degree = sum(dict(graph.degree()).values())
        num_nodes = graph.number_of_nodes()
        avg_degree = total_degree / num_nodes if num_nodes > 0 else 0
        return avg_degree

    def todict(self, graph: nx.Graph) -> Dict[str, float]:
        avg_degree = ComputeAverageDegree()(graph)
        return {
            'average_degree': avg_degree,
        }

    def print(self, graph: nx.Graph):
        avg_degree = ComputeAverageDegree()(graph)
        print(f"Average Degree: {avg_degree}")
