"""
Visualization Presenter - Creates visualizations for analysis results.
"""
from typing import Dict, Any, List, Tuple, Optional
import os
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import networkx as nx
from datetime import datetime
import seaborn as sns
import numpy as np

from src.domain.entities.flow import Flow, FlowState
from src.domain.entities.attack import Attack, AttackType
from src.use_cases.visualize_flow_use_case import VisualizationStrategy


class MatplotlibVisualizationStrategy(VisualizationStrategy):
    """Visualization strategy implementation using Matplotlib."""
    
    def __init__(self, output_dir: str = "visualizations"):
        """
        Initialize the Matplotlib visualization strategy.
        
        Args:
            output_dir: Directory to save visualizations
        """
        self.output_dir = output_dir
        
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
    
    def create_flow_graph(self, flows: List[Flow], title: str) -> str:
        """
        Create a graph visualization of network flows.
        
        Args:
            flows: List of Flow entities
            title: Title for the visualization
            
        Returns:
            Path to the saved visualization file
        """
        # Create a new figure
        plt.figure(figsize=(12, 8))
        
        # Create a directed graph
        G = nx.DiGraph()
        
        # Group nodes by IP to avoid excessive nodes
        ip_nodes = {}
        
        # Add nodes and edges for each flow
        for flow in flows:
            # Create source and destination node labels
            src_label = f"{flow.src_ip}"
            dst_label = f"{flow.dst_ip}"
            
            # Add nodes if they don't exist
            if src_label not in ip_nodes:
                G.add_node(src_label, type="source")
                ip_nodes[src_label] = True
            
            if dst_label not in ip_nodes:
                G.add_node(dst_label, type="destination")
                ip_nodes[dst_label] = True
            
            # Determine edge color based on flow state
            if hasattr(flow, 'state'):
                if flow.state == FlowState.ESTABLISHED:
                    color = 'green'
                elif flow.state == FlowState.CLOSED:
                    color = 'blue'
                elif flow.state == FlowState.RESET:
                    color = 'red'
                else:
                    color = 'gray'
            else:
                color = 'gray'
            
            # Add an edge with packet count as weight and appropriate color
            G.add_edge(
                src_label, 
                dst_label, 
                weight=max(1, flow.packet_count/10),  # Scale for visibility
                color=color,
                packets=flow.packet_count
            )
        
        # Use spring layout for node positions
        pos = nx.spring_layout(G, seed=42)
        
        # Extract edge colors and weights
        edges = G.edges()
        edge_colors = [G[u][v]['color'] for u, v in edges]
        edge_weights = [G[u][v]['weight'] for u, v in edges]
        
        # Draw the network graph
        nx.draw_networkx_nodes(G, pos, node_size=300, alpha=0.8)
        nx.draw_networkx_edges(G, pos, width=edge_weights, edge_color=edge_colors, alpha=0.7, 
                              arrowsize=15, connectionstyle='arc3,rad=0.1')
        nx.draw_networkx_labels(G, pos, font_size=10)
        
        # Create a legend for flow states
        legend_elements = [
            plt.Line2D([0], [0], color='green', lw=2, label='Established'),
            plt.Line2D([0], [0], color='blue', lw=2, label='Closed'),
            plt.Line2D([0], [0], color='red', lw=2, label='Reset'),
            plt.Line2D([0], [0], color='gray', lw=2, label='Other')
        ]
        plt.legend(handles=legend_elements, loc='upper right')
        
        # Set title and turn off axis
        plt.title(title)
        plt.axis('off')
        
        # Generate output file path
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = os.path.join(self.output_dir, f"flow_graph_{timestamp}.png")
        
        # Save the figure
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        plt.close()
        
        return output_file
    
    def create_time_series(self, data: List[Tuple[datetime, float]], title: str, y_label: str) -> str:
        """
        Create a time series visualization.
        
        Args:
            data: List of (timestamp, value) tuples
            title: Title for the visualization
            y_label: Label for the y-axis
            
        Returns:
            Path to the saved visualization file
        """
        if not data:
            return ""
        
        # Create a new figure
        plt.figure(figsize=(12, 6))
        
        # Extract timestamps and values
        timestamps = [entry[0] for entry in data]
        values = [entry[1] for entry in data]
        
        # Plot the time series
        plt.plot(timestamps, values, marker='o', linestyle='-', alpha=0.7)
        
        # Format x-axis as times
        plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
        plt.gcf().autofmt_xdate()
        
        # Set labels and title
        plt.xlabel('Time')
        plt.ylabel(y_label)
        plt.title(title)
        plt.grid(True, alpha=0.3)
        
        # Generate output file path
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = os.path.join(self.output_dir, f"time_series_{timestamp}.png")
        
        # Save the figure
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        plt.close()
        
        return output_file
    
    def create_attack_visualization(self, attacks: List[Attack], title: str) -> str:
        """
        Create a visualization of detected attacks.
        
        Args:
            attacks: List of Attack entities
            title: Title for the visualization
            
        Returns:
            Path to the saved visualization file
        """
        if not attacks:
            return ""
        
        # Create a new figure with two subplots
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 10), gridspec_kw={'height_ratios': [2, 1]})
        
        # ----- First subplot: Attack timeline -----
        
        # Extract timestamps and attack types
        timestamps = [datetime.fromisoformat(attack.timestamp) if isinstance(attack.timestamp, str) 
                     else attack.timestamp for attack in attacks]
        attack_types = [attack.attack_type.value if hasattr(attack.attack_type, 'value') 
                       else attack.attack_type for attack in attacks]
        severities = [attack.severity for attack in attacks]
        
        # Create a colormap based on severity
        cmap = plt.cm.get_cmap('YlOrRd')
        colors = [cmap(severity/10) for severity in severities]
        
        # Plot attacks on timeline
        ax1.scatter(timestamps, attack_types, c=colors, s=100, alpha=0.7)
        
        # Format x-axis as times
        ax1.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
        fig.autofmt_xdate()
        
        # Set labels and title
        ax1.set_xlabel('Time')
        ax1.set_ylabel('Attack Type')
        ax1.set_title('Attack Timeline')
        ax1.grid(True, alpha=0.3)
        
        # ----- Second subplot: Attack type distribution -----
        
        # Count attacks by type
        attack_counts = {}
        for attack in attacks:
            attack_type = attack.attack_type.value if hasattr(attack.attack_type, 'value') else attack.attack_type
            attack_counts[attack_type] = attack_counts.get(attack_type, 0) + 1
        
        # Create bar chart
        x = list(attack_counts.keys())
        y = list(attack_counts.values())
        
        # Create colormap based on count
        bar_colors = plt.cm.viridis(np.array(y) / max(y))
        
        ax2.bar(x, y, color=bar_colors, alpha=0.7)
        ax2.set_xlabel('Attack Type')
        ax2.set_ylabel('Count')
        ax2.set_title('Attack Distribution by Type')
        
        # Rotate x-axis labels for better readability
        plt.setp(ax2.get_xticklabels(), rotation=45, ha='right')
        
        # Add a colorbar legend
        sm = plt.cm.ScalarMappable(cmap=plt.cm.viridis, norm=plt.Normalize(vmin=min(y), vmax=max(y)))
        sm.set_array([])
        cbar = plt.colorbar(sm, ax=ax2)
        cbar.set_label('Count')
        
        # Adjust layout
        plt.tight_layout()
        
        # Set overall title
        fig.suptitle(title, fontsize=16, y=0.98)
        plt.subplots_adjust(top=0.90)
        
        # Generate output file path
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = os.path.join(self.output_dir, f"attack_visualization_{timestamp}.png")
        
        # Save the figure
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        plt.close()
        
        return output_file
    
    def create_protocol_distribution(self, counts: Dict[str, int], title: str) -> str:
        """
        Create a visualization of protocol distribution.
        
        Args:
            counts: Dictionary mapping protocol names to counts
            title: Title for the visualization
            
        Returns:
            Path to the saved visualization file
        """
        if not counts:
            return ""
        
        # Create a new figure
        plt.figure(figsize=(10, 6))
        
        # Use a nicer color palette
        colors = sns.color_palette("Set3", len(counts))
        
        # Create a pie chart
        labels = list(counts.keys())
        sizes = list(counts.values())
        
        plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', 
                shadow=False, startangle=140, textprops={'fontsize': 10})
        
        # Equal aspect ratio ensures that pie is drawn as a circle
        plt.axis('equal')
        
        # Set title
        plt.title(title)
        
        # Generate output file path
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = os.path.join(self.output_dir, f"protocol_distribution_{timestamp}.png")
        
        # Save the figure
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        plt.close()
        
        return output_file 