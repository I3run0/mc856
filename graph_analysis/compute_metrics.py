import random
import json
import networkx as nx
import pandas as pd
import argparse
from metrics.packages_reached_by_vuln import ComputePackagesReachedByVuln
from metrics.clustering_coefficient import ComputeClusteringCoefficient
from metrics.degrees import ComputeOutDegree, ComputeInDegree, ComputeAverageDegree
from metrics.number_of_vul_per_packages import ComputeVulPackagesSucessor
from metrics.percentage_of_the_network_reached_by_set import ComputePctgOftheNetworkReached
from metrics.centralities import BetweennessCentrality, ClosenessCentrality, EigenvectorCentrality, DegreeCentrality
from metrics.number_of_reachable_packages import ComputeNumOfReachablePkgs
from metrics.longest_path import ComputeLongestPath
from metrics.pagerank import ComputePageRank
from metrics.nodes_and_edges import ComputeNodesAndEdges, ComputeDensity
from graph_builder import build_dependency_graph_from_json


def save_results_to_json(results, filename='metrics_results.json'):
    with open(filename, 'w') as f:
        json.dump(results, f, indent=4)
    print(f"Results saved to {filename}")


def compute_metrics(graph: nx.Graph, metric_class, subset=None):
    print(f"Computing {metric_class.__class__.__name__}...")
    if metric_class == ComputePctgOftheNetworkReached:
        result = metric_class().todict(graph, subset)
    else:
        result = metric_class().todict(graph)
    return result


def main():
    parser = argparse.ArgumentParser(description="Compute and save graph metrics")
    
    subparsers = parser.add_subparsers(dest="metric_names", help="Available metrics")

    subcommands = {
        'pagerank': ComputePageRank,
        'clustering_coefficient': ComputeClusteringCoefficient,
        'out_degree': ComputeOutDegree,
        'in_degree': ComputeInDegree,
        'average_degree': ComputeAverageDegree,
        'num_of_vul_per_package': ComputeVulPackagesSucessor,
        'percentage_of_network_reached': ComputePctgOftheNetworkReached,
        'betweenness_centrality': BetweennessCentrality,
        'closeness_centrality': ClosenessCentrality,
        'eigenvector_centrality': EigenvectorCentrality,
        'degree_centrality': DegreeCentrality,
        'num_of_reachable_packages': ComputeNumOfReachablePkgs,
        'longest_path': ComputeLongestPath,
        'nodes_and_edges': ComputeNodesAndEdges,
        'density': ComputeDensity
    }

    for metric, metric_class in subcommands.items():
        subparser = subparsers.add_parser(metric, help=f"Compute {metric.replace('_', ' ').capitalize()}")
        subparser.add_argument(
            '--input-file', 
            type=str, 
            required=True, 
            help="Path to the file used to construct the graph"
        )
        subparser.add_argument(
            '--subset-size', 
            type=int, 
            default=5, 
            help="Size of the subset of nodes (default is 5)"
        )
        subparser.add_argument(
            '--output-file', 
            type=str, 
            default="metrics_results.json", 
            help="Name of the output JSON file (default is metrics_results.json)"
        )

    args = parser.parse_args()
    graph = build_dependency_graph_from_json(args.input_file)  
    results = {}

    if args.metric_names:
        metric_class = subcommands[args.metric_names]
        subset = random.sample(list(graph.nodes()), args.subset_size)
        result = compute_metrics(graph, metric_class, subset)
        results[args.metric_names] = result

    save_results_to_json(results, args.output_file)


if __name__ == '__main__':
    main()
