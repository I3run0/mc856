import networkx as nx
from abc import ABC, abstractmethod

class GraphMetrics(ABC):
    """
    Abstract class to define the interface for computing graph metrics.
    This class should be inherited and extended for different types of metrics.
    """
    @abstractmethod
    def __call__(self, graph: nx.Graph):
        """Compute the metric for the given graph."""
        pass
    
    @abstractmethod
    def todict(self, graph: nx.Graph):
        """Compute the metric and parse to a dict format."""
        pass

    @abstractmethod
    def print(self, graph: nx.graph):
        """Compute the metric and parse to a print format."""
        pass