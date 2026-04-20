#!/usr/bin/env python3
"""
BugCrusher — Graph-Based Attack Pathfinder
Maps attack surfaces as graphs and finds optimal paths to crown jewels.
"""

import json
import heapq
from collections import defaultdict
from typing import Dict, List, Set, Tuple, Optional

class AttackGraph:
    def __init__(self):
        # Graph: node -> [(neighbor, edge_data)]
        self.graph: Dict[str, List[Tuple[str, dict)]] = defaultdict(list)
        self.nodes: Set[str] = set()
        self.edges: List[Tuple[str, str, dict]] = []
        
        # Node types
        self.node_types: Dict[str, str] = {}
        
        # Crown jewels
        self.crown_jewels: Set[str] = set()
    
    def add_node(self, node_id: str, node_type: str, metadata: dict = None):
        """Add a node to the attack graph."""
        self.nodes.add(node_id)
        self.node_types[node_id] = node_type
        if metadata:
            setattr(self, f"meta_{node_id}", metadata)
    
    def add_edge(self, from_node: str, to_node: str, exploit: str, 
                 cost: float = 1.0, detection_risk: float = 0.5, 
                 success_prob: float = 1.0, metadata: dict = None):
        """Add an edge (exploit path) between nodes."""
        if from_node not in self.nodes or to_node not in self.nodes:
            return False
        
        edge_data = {
            'exploit': exploit,
            'cost': cost,
            'detection_risk': detection_risk,
            'success_prob': success_prob,
            'metadata': metadata or {}
        }
        
        self.graph[from_node].append((to_node, edge_data))
        self.edges.append((from_node, to_node, edge_data))
        return True
    
    def set_crown_jewels(self, nodes: List[str]):
        """Define crown jewel targets."""
        self.crown_jewels = set(nodes)
        for node in nodes:
            self.nodes.add(node)
    
    def bfs_shortest(self, start: str, goal: str = None) -> List[str]:
        """BFS — shortest path (stealth priority)."""
        if goal is None:
            goal = list(self.crown_jewels)[0] if self.crown_jewels else None
        
        if not goal:
            return []
        
        queue = [(start, [start])]
        visited = {start}
        
        while queue:
            node, path = queue.pop(0)
            
            if node == goal:
                return path
            
            for neighbor, _ in self.graph[node]:
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, path + [neighbor]))
        
        return []
    
    def dfs_deepest(self, start: str, goal: str = None, max_depth: int = 10) -> List[str]:
        """DFS — deepest path first (thoroughness priority)."""
        def dfs_recursive(node: str, path: List[str], depth: int) -> List[str]:
            if depth > max_depth:
                return []
            
            if goal and node == goal:
                return path
            
            deepest = []
            for neighbor, _ in self.graph[node]:
                if neighbor not in path:
                    result = dfs_recursive(neighbor, path + [neighbor], depth + 1)
                    if result and len(result) > len(deepest):
                        deepest = result
            
            return deepest
        
        return dfs_recursive(start, [start], 0)
    
    def dijkstra_weighted(self, start: str, goal: str = None) -> Tuple[List[str], float]:
        """Dijkstra — weighted by exploit difficulty (resource priority)."""
        if goal is None:
            goal = list(self.crown_jewels)[0] if self.crown_jewels else None
        
        if not goal:
            return [], float('inf')
        
        # Weight = cost * (1 / success_prob) * (1 + detection_risk)
        distances = {node: float('inf') for node in self.nodes}
        distances[start] = 0
        predecessors = {node: None for node in self.nodes}
        
        pq = [(0, start)]
        visited = set()
        
        while pq:
            current_dist, node = heapq.heappop(pq)
            
            if node in visited:
                continue
            visited.add(node)
            
            if node == goal:
                break
            
            for neighbor, edge_data in self.graph[node]:
                if neighbor in visited:
                    continue
                
                weight = edge_data['cost'] * (1 / edge_data['success_prob']) * (1 + edge_data['detection_risk'])
                new_dist = current_dist + weight
                
                if new_dist < distances[neighbor]:
                    distances[neighbor] = new_dist
                    predecessors[neighbor] = node
                    heapq.heappush(pq, (new_dist, neighbor))
        
        # Reconstruct path
        path = []
        current = goal
        while current:
            path.append(current)
            current = predecessors[current]
        
        path.reverse()
        return path if path[0] == start else [], distances[goal]
    
    def astar_heuristic(self, node: str, goal: str) -> float:
        """A* heuristic — straight-line distance approximation."""
        # Simplified: use inverse of exploit difficulty as heuristic
        return 0.5  # Placeholder - would need coordinate mapping for real heuristic
    
    def astar(self, start: str, goal: str = None) -> List[str]:
        """A* — heuristic-guided search (targeting specific assets)."""
        if goal is None:
            goal = list(self.crown_jewels)[0] if self.crown_jewels else None
        
        if not goal:
            return []
        
        g_score = {node: float('inf') for node in self.nodes}
        g_score[start] = 0
        
        f_score = {node: float('inf') for node in self.nodes}
        f_score[start] = self.astar_heuristic(start, goal)
        
        open_set = [(f_score[start], start)]
        came_from = {node: None for node in self.nodes}
        in_open = {start}
        
        while open_set:
            _, current = heapq.heappop(open_set)
            in_open.discard(current)
            
            if current == goal:
                path = []
                while current:
                    path.append(current)
                    current = came_from[current]
                path.reverse()
                return path
            
            for neighbor, edge_data in self.graph[current]:
                if neighbor in in_open:
                    continue
                
                tentative_g = g_score[current] + edge_data['cost']
                
                if tentative_g < g_score[neighbor]:
                    came_from[neighbor] = current
                    g_score[neighbor] = tentative_g
                    f_score[neighbor] = tentative_g + self.astar_heuristic(neighbor, goal)
                    heapq.heappush(open_set, (f_score[neighbor], neighbor))
                    in_open.add(neighbor)
        
        return []
    
    def find_all_paths(self, start: str, goal: str, max_depth: int = 10) -> List[List[str]]:
        """Find all paths between start and goal (limited depth)."""
        all_paths = []
        
        def dfs_all(node: str, path: List[str], depth: int):
            if depth > max_depth:
                return
            
            if node == goal:
                all_paths.append(path[:])
                return
            
            for neighbor, _ in self.graph[node]:
                if neighbor not in path:
                    dfs_all(neighbor, path + [neighbor], depth + 1)
        
        dfs_all(start, [start], 0)
        return all_paths
    
    def rank_paths(self, paths: List[List[str]], metric: str = 'impact') -> List[Tuple[List[str], float]]:
        """Rank paths by various metrics."""
        scored_paths = []
        
        for path in paths:
            score = 0
            
            if metric == 'cost':
                score = sum(self._get_edge_weight(p) for p in self._path_edges(path))
            elif metric == 'detection':
                score = sum(self._get_edge_weight(p, key='detection_risk') for p in self._path_edges(path))
            elif metric == 'impact':
                score = len(path) * 0.5  # Longer paths = more impact potential
            
            scored_paths.append((path, score))
        
        scored_paths.sort(key=lambda x: x[1], reverse=(metric != 'cost'))
        return scored_paths
    
    def _get_edge_weight(self, edge_tuple: Tuple, key: str = 'cost') -> float:
        """Get edge weight by key."""
        return edge_tuple[2].get(key, 1.0)
    
    def _path_edges(self, path: List[str]) -> List[Tuple]:
        """Get edges along a path."""
        edges = []
        for i in range(len(path) - 1):
            for neighbor, edge_data in self.graph[path[i]]:
                if neighbor == path[i + 1]:
                    edges.append((path[i], path[i + 1], edge_data))
                    break
        return edges
    
    def generate_report(self, start_node: str) -> dict:
        """Generate comprehensive pathfinding report."""
        report = {
            'start': start_node,
            'crown_jewels': list(self.crown_jewels),
            'shortest_path': self.bfs_shortest(start_node),
            'deepest_path': self.dfs_deepest(start_node),
            'optimal_path': self.dijkstra_weighted(start_node)[0],
            'astar_path': self.astar(start_node),
            'all_paths': []
        }
        
        for jewel in self.crown_jewels:
            paths = self.find_all_paths(start_node, jewel)
            ranked = self.rank_paths(paths)
            report['all_paths'].append({
                'target': jewel,
                'path_count': len(paths),
                'top_paths': ranked[:5]
            })
        
        return report
    
    def to_json(self) -> str:
        """Export graph as JSON."""
        data = {
            'nodes': {n: {'type': self.node_types.get(n)} for n in self.nodes},
            'edges': [(e[0], e[1], e[2]) for e in self.edges],
            'crown_jewels': list(self.crown_jewels)
        }
        return json.dumps(data, indent=2)
    
    @staticmethod
    def from_json(json_str: str) -> 'AttackGraph':
        """Load graph from JSON."""
        data = json.loads(json_str)
        graph = AttackGraph()
        
        for node_id, node_data in data['nodes'].items():
            graph.add_node(node_id, node_data.get('type', 'unknown'))
        
        for edge in data['edges']:
            graph.add_edge(edge[0], edge[1], **edge[2])
        
        for jewel in data.get('crown_jewels', []):
            graph.crown_jewels.add(jewel)
        
        return graph


def demo():
    """Demo: Build a sample attack graph."""
    graph = AttackGraph()
    
    # Add nodes
    graph.add_node('internet', 'location')
    graph.add_node('web_server', 'host', {'os': 'linux', 'services': ['nginx', 'php-fpm']})
    graph.add_node('admin_panel', 'webapp', {'url': '/admin', 'auth': 'basic']})
    graph.add_node('database', 'host', {'db': 'mysql']})
    graph.add_node('internal_file_server', 'host', {'purpose': 'file storage'})
    graph.add_node('domain_controller', 'host', {'role': 'AD'}),
    graph.add_node('crown_jewel', 'data', {'type': 'credentials_db'})
    
    # Define crown jewels
    graph.set_crown_jewels(['crown_jewel', 'domain_controller'])
    
    # Add edges (exploit paths)
    graph.add_edge('internet', 'web_server', 'Nginx exploit', cost=2, detection_risk=0.3, success_prob=0.8)
    graph.add_edge('web_server', 'admin_panel', 'SQLi to Auth Bypass', cost=3, detection_risk=0.5, success_prob=0.7)
    graph.add_edge('admin_panel', 'database', 'Command Injection → DB Access', cost=5, detection_risk=0.7, success_prob=0.9)
    graph.add_edge('database', 'internal_file_server', 'Lateral Movement via DB', cost=4, detection_risk=0.4, success_prob=0.6)
    graph.add_edge('internal_file_server', 'domain_controller', 'SMB Exploit', cost=6, detection_risk=0.6, success_prob=0.5)
    graph.add_edge('web_server', 'database', 'Webshell → Direct DB', cost=4, detection_risk=0.8, success_prob=0.9)
    
    # Generate report
    report = graph.generate_report('internet')
    print(json.dumps(report, indent=2))
    
    return graph


if __name__ == '__main__':
    demo()
