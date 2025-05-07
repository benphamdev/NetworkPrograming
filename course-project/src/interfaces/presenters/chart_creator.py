"""
Chart Creator - Các hàm tạo biểu đồ và trực quan hóa cho Gradio Presenter
"""
from typing import Dict, List
import plotly.express as px
import plotly.graph_objects as go
import networkx as nx

class ChartCreator:
    """Tạo biểu đồ và trực quan hóa cho phân tích gói tin."""
    
    @staticmethod
    def create_protocol_chart(results: Dict) -> Dict:
        """Tạo biểu đồ phân bố giao thức bằng Plotly."""
        if not results or "flow_statistics" not in results:
            return None
            
        # Tạo dữ liệu mẫu về giao thức nếu không có sẵn
        protocols = {
            "TCP": results["flow_statistics"].get("established_count", 0) + 
                  results["flow_statistics"].get("reset_count", 0) + 
                  results["flow_statistics"].get("closed_count", 0),
            "UDP": results["flow_statistics"].get("total_flows", 0) // 4,  # Ước tính
            "ICMP": results["flow_statistics"].get("total_flows", 0) // 8,  # Ước tính
            "ARP": results["flow_statistics"].get("total_flows", 0) // 6   # Ước tính
        }
        
        # Lọc ra các giá trị bằng 0
        protocols = {k: v for k, v in protocols.items() if v > 0}
        
        # Tạo biểu đồ tròn
        fig = px.pie(
            values=list(protocols.values()),
            names=list(protocols.keys()),
            title="Phân bố giao thức",
            color_discrete_sequence=px.colors.qualitative.Set3
        )
        fig.update_traces(textposition='inside', textinfo='percent+label')
        
        return fig
    
    @staticmethod
    def create_attack_severity_chart(attacks: List[Dict]) -> Dict:
        """Tạo biểu đồ mức độ nghiêm trọng của tấn công bằng Plotly."""
        if not attacks:
            return None
            
        # Nhóm các tấn công theo loại và tính toán mức độ nghiêm trọng trung bình
        attack_types = {}
        for attack in attacks:
            attack_type = attack.get("attack_type", "Unknown")
            severity = attack.get("severity", 0)
            
            if attack_type not in attack_types:
                attack_types[attack_type] = {"count": 0, "total_severity": 0}
                
            attack_types[attack_type]["count"] += 1
            attack_types[attack_type]["total_severity"] += severity
        
        # Tính mức độ nghiêm trọng trung bình
        for attack_type in attack_types:
            attack_types[attack_type]["avg_severity"] = (
                attack_types[attack_type]["total_severity"] / attack_types[attack_type]["count"]
            )
        
        # Tạo biểu đồ cột
        fig = go.Figure()
        fig.add_trace(go.Bar(
            x=list(attack_types.keys()),
            y=[info["count"] for info in attack_types.values()],
            name="Số lượng",
            marker_color="indianred"
        ))
        
        fig.add_trace(go.Bar(
            x=list(attack_types.keys()),
            y=[info["avg_severity"] for info in attack_types.values()],
            name="Mức độ nghiêm trọng TB",
            marker_color="lightsalmon"
        ))
        
        fig.update_layout(
            title="Phân bố và mức độ nghiêm trọng của tấn công",
            xaxis_title="Loại tấn công",
            yaxis_title="Giá trị",
            barmode="group"
        )
        
        return fig
    
    @staticmethod
    def create_flow_graph(results: Dict) -> Dict:
        """Tạo trực quan hóa đồ thị luồng mạng bằng Plotly."""
        # Nếu không có kết quả, trả về None
        if not results or "flow_statistics" not in results:
            return None
        
        # Tạo đồ thị có hướng
        G = nx.DiGraph()
        
        # Thêm các nút và cạnh mẫu
        ips = [
            "192.168.1.1", "192.168.1.2", "192.168.1.100", 
            "192.168.1.101", "8.8.8.8", "1.1.1.1"
        ]
        
        # Thêm nút
        for ip in ips:
            G.add_node(ip)
        
        # Thêm cạnh với trọng số khác nhau
        edges = [
            ("192.168.1.1", "8.8.8.8", 10),
            ("192.168.1.2", "1.1.1.1", 5),
            ("192.168.1.100", "8.8.8.8", 8),
            ("192.168.1.101", "1.1.1.1", 3),
            ("192.168.1.1", "192.168.1.100", 2),
            ("192.168.1.2", "192.168.1.101", 4)
        ]
        
        for src, dst, weight in edges:
            G.add_edge(src, dst, weight=weight)
        
        # Sử dụng layout force-directed
        pos = nx.spring_layout(G)
        
        # Tạo thông tin cạnh
        edge_x = []
        edge_y = []
        edge_width = []
        
        for edge in G.edges(data=True):
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])
            edge_width.append(edge[2].get('weight', 1))
        
        edge_trace = go.Scatter(
            x=edge_x, y=edge_y,
            line=dict(width=1, color='#888'),
            hoverinfo='none',
            mode='lines')
        
        # Tạo thông tin nút
        node_x = []
        node_y = []
        node_text = []
        
        for node in G.nodes():
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)
            node_text.append(node)
        
        node_trace = go.Scatter(
            x=node_x, y=node_y,
            mode='markers',
            hoverinfo='text',
            text=node_text,
            marker=dict(
                showscale=True,
                colorscale='YlGnBu',
                size=10,
                colorbar=dict(
                    thickness=15,
                    title=dict(
                        side="right"
                    ),
                    xanchor='left'
                ),
                color=[len(G.edges(node)) for node in G.nodes()],
                line_width=2))
        
        # Tạo biểu đồ
        fig = go.Figure(data=[edge_trace, node_trace],
                      layout=go.Layout(
                          title=dict(
                              text="Biểu đồ luồng mạng",
                              font=dict(size=16)
                          ),
                          showlegend=False,
                          hovermode='closest',
                          margin=dict(b=20,l=5,r=5,t=40),
                          xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                          yaxis=dict(showgrid=False, zeroline=False, showticklabels=False))
                      )
        
        return fig
        
    @staticmethod
    def create_tcp_visualizations(results: Dict) -> Dict:
        """Tạo trực quan hóa phân tích TCP."""
        if not results:
            return None
            
        # Tạo ví dụ về phân bố cờ TCP
        tcp_flags = {
            "SYN": 15,
            "SYN-ACK": 12,
            "ACK": 38,
            "FIN": 8,
            "RST": 3,
            "PSH": 18,
            "URG": 1
        }
        
        fig = go.Figure()
        fig.add_trace(go.Bar(
            x=list(tcp_flags.keys()),
            y=list(tcp_flags.values()),
            marker_color="cornflowerblue"
        ))
        
        fig.update_layout(
            title=dict(
                text="Phân bố cờ TCP",
                font=dict(size=16)
            ),
            xaxis_title="Loại cờ TCP",
            yaxis_title="Số lượng"
        )
        
        return fig 