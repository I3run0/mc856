import networkx as nx
from typing import Dict, Tuple
import pandas as pd
from metrics.abstract_metrics import GraphMetrics

class ComputeLongestPath(GraphMetrics):
    def __call__(self, graph: nx.Graph, start_node: str) -> Tuple[int, list]:
        """Compute the longest path from the start_node in the subgraph."""
        
        # A função BFS/DFS para calcular a distância máxima
        def dfs(node, visited, path_length, current_path):
            visited.add(node)
            longest = path_length
            longest_path = current_path

            for neighbor in graph.neighbors(node):
                if neighbor not in visited:
                    new_path_length, new_path = dfs(neighbor, visited.copy(), path_length + 1, current_path + [neighbor])
                    if new_path_length > longest:
                        longest = new_path_length
                        longest_path = new_path
            return longest, longest_path

        # Inicia a busca a partir do nó de origem
        longest_path_length, longest_path = dfs(start_node, set(), 0, [start_node])
        return longest_path_length, longest_path

    def todict(self, graph: nx.Graph, start_node: str) -> Dict[str, Tuple[int, list]]:
        longest_path_length, longest_path = self.__call__(graph, start_node)
        return {
            'longest_path': {
                'start_node': start_node,
                'length': longest_path_length,
                'path': longest_path
            }
        }

    def print(self, graph: nx.Graph, start_node: str):
        longest_path_length, longest_path = self.__call__(graph, start_node)
        print(f"Longest path from node {start_node}:")
        print(f"    Length: {longest_path_length}")
        print(f"    Path: {longest_path}")

    def to_dataframe(self, graph: nx.Graph, start_node: str) -> pd.DataFrame:
        """Convert the longest path information into a DataFrame."""
        longest_path_length, longest_path = self.__call__(graph, start_node)
        
        # Create a DataFrame
        df = pd.DataFrame({
            'Start_Node': [start_node],
            'Longest_Path_Length': [longest_path_length],
            'Longest_Path': [longest_path]
        })
        
        return df
