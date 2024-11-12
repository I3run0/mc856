from metrics.abstract_metrics import GraphMetrics
import networkx as nx
import pandas as pd
from typing import Dict

class ComputePageRank(GraphMetrics):
    def __call__(self, graph: nx.Graph) -> dict:
        """Compute the pagerank of the graph."""
        return nx.pagerank(graph)

    def todict(self, graph: nx.Graph) -> Dict[str, dict]:
        pagerank = self.__call__(graph)
        return {'pagerank': pagerank}

    def to_dataframe(self, graph: nx.Graph) -> pd.DataFrame:
        """Convert the PageRank result to a DataFrame."""
        pagerank = self.__call__(graph)
        return pd.DataFrame(list(pagerank.items()), columns=['Node', 'PageRank'])

    def print(self, graph: nx.Graph):
        pagerank = self.__call__(graph)
        print("PageRank of each node in the graph:")
        for node, rank in pagerank.items():
            print(f'    Node: {node}; PageRank: {rank}')
