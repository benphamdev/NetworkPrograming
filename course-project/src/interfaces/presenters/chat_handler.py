"""
ChatHandler - Quản lý hội thoại chat với người dùng về phân tích mạng.
Lớp này xử lý các truy vấn từ người dùng và tạo phản hồi dựa trên kết quả phân tích từ file PCAP.
Nó là con của Gradio gateway
"""
from typing import Dict, List, Optional, Any, Tuple
import os
import re
from collections import Counter
from src.interfaces.gateways.smolagent_gateway import SmolagentGateway
from src.interfaces.gateways.protocol_analyzer import ProtocolAnalyzer
from src.interfaces.presenters.summary_creator import SummaryCreator

class ChatHandler:
    """Quản lý hội thoại chat với người dùng về phân tích mạng."""
    
    def __init__(self, smolagent_gateway: Optional[SmolagentGateway] = None, protocol_analyzer: Optional[ProtocolAnalyzer] = None):
        """
        Khởi tạo chat handler.
        
        Args:
            smolagent_gateway: Gateway cho Smolagent
            protocol_analyzer: Bộ phân tích giao thức
        """
        self.chat_history: List[Dict[str, str]] = []
        self.latest_pcap_file: Optional[str] = None
        self.latest_results: Optional[Dict[str, Any]] = None
        self.smolagent_gateway = smolagent_gateway if smolagent_gateway is not None else SmolagentGateway()
        self.protocol_analyzer = protocol_analyzer if protocol_analyzer is not None else ProtocolAnalyzer(self.smolagent_gateway)
        self.summary_creator = SummaryCreator()
    
    def set_latest_results(self, results: Optional[Dict[str, Any]]):
        """Cập nhật kết quả phân tích mới nhất."""
        self.latest_results = results

    def set_latest_pcap_file(self, pcap_file: Optional[str]):
        """Cập nhật file PCAP mới nhất."""
        self.latest_pcap_file = pcap_file

    def update_chat_history(self, chat_history: List[Dict[str, str]]):
        """Cập nhật lịch sử chat."""
        self.chat_history = list(chat_history)

    def _get_effective_results(self, results_param: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Determines the effective results to use: parameter if provided, else internal state."""
        if results_param is not None:
            return results_param
        return self.latest_results

    def get_context_for_general_query(self, results_param: Optional[Dict[str, Any]]) -> str:
        """Tạo ngữ cảnh từ kết quả phân tích cho truy vấn chung."""
        current_results = self._get_effective_results(results_param)
        if not current_results or not current_results.get("packets"):
            return "Không có dữ liệu gói tin."

        summary_parts = []
        packets = current_results.get("packets", [])
        total_packets = len(packets)
        summary_parts.append(f"Tổng số {total_packets} gói tin.")

        summary_data = current_results.get("summary", {})
        if "start_time" in summary_data and "end_time" in summary_data:
            summary_parts.append(f"Thời gian ghi từ {summary_data['start_time']} đến {summary_data['end_time']}.")
        
        protocol_dist = current_results.get("protocol_distribution")
        if protocol_dist and isinstance(protocol_dist, dict):
            protocols = ", ".join([f"{p} ({c})" for p, c in protocol_dist.items()])
            summary_parts.append(f"Các giao thức chính: {protocols}.")

        attacks_data = current_results.get("attacks")
        if attacks_data and isinstance(attacks_data, list):
            attack_types = set()
            for attack in attacks_data:
                if isinstance(attack, dict) and "type" in attack:
                    attack_types.add(str(attack["type"]))
            if attack_types:
                summary_parts.append(f"Phát hiện các loại tấn công tiềm ẩn: {', '.join(attack_types)}.")

        if not summary_parts or (len(summary_parts) == 1 and total_packets == 0):
            return f"Dữ liệu gồm {total_packets} gói tin." if total_packets > 0 else "Không có dữ liệu gói tin."
        return " ".join(summary_parts)

    def create_ai_chat_response(self, query: str, results_param: Optional[Dict[str, Any]] = None) -> str:
        current_results = self._get_effective_results(results_param)

        if results_param is not None:
            self.set_latest_results(results_param)

        query_lower = query.lower()

        if "phân tích chi tiết theo mô hình osi" in query_lower or "osi model analysis" in query_lower:
            return self._get_osi_analysis(current_results)

        attack_keywords = ["tấn công", "attack", "spoofing", "dấu hiệu arp", "syn flood", "dos", "exploit", "vulnerability", "malware", "ddos", "port scan", "quét cổng"]
        if any(keyword in query_lower for keyword in attack_keywords):
            return self._analyze_attack_query(query, current_results)

        if self._detect_protocol_query(query_lower):
            protocol = self._extract_protocol_from_query(query_lower)
            if protocol:
                return self._analyze_protocol_query(protocol, query, current_results)

        if "cờ tcp" in query_lower or "tcp flag" in query_lower or "phân tích cờ" in query_lower:
            return self._analyze_tcp_flags(current_results)

        if "dự đoán" in query_lower or "có thể xảy ra" in query_lower or "khả năng" in query_lower:
            return self._predict_network_issues(current_results)

        if "thông số nguy hiểm" in query_lower or "gói tin nguy hiểm" in query_lower or "thông số bất thường" in query_lower or "payload độc hại" in query_lower:
            return self._analyze_dangerous_parameters(current_results)

        context_for_agent = self.get_context_for_general_query(current_results)
        if "Không có dữ liệu gói tin." in context_for_agent and not ("tải lên file pcap" in query_lower or "hướng dẫn" in query_lower or "upload pcap" in query_lower):
            return "Không có dữ liệu gói tin để phân tích. Vui lòng tải lên file PCAP để tôi có thể hỗ trợ bạn."

        try:
            if not self.smolagent_gateway:
                return "Lỗi: Smolagent gateway chưa được khởi tạo."
            
            prompt = f"User query: \"{query}\". \nAvailable data context: \"{context_for_agent}\"."
            if self.latest_pcap_file:
                prompt += f"\nAnalysis is based on file: {self.latest_pcap_file}."
            
            response = self.smolagent_gateway.general_agent.run(prompt)
            return response
        except Exception as e:
            return f"Đã có lỗi xảy ra khi xử lý yêu cầu của bạn: {str(e)}"

    def _get_osi_analysis(self, results_param: Optional[Dict[str, Any]]) -> str:
        current_results = self._get_effective_results(results_param)
        if not current_results or not current_results.get("packets"):
            return "Không có dữ liệu gói tin để tạo phân tích OSI. Vui lòng tải lên file PCAP."
        try:
            return self.smolagent_gateway.osi_agent.run(results_summary=str(current_results.get("summary", {})), packets_data=current_results.get("packets", []))
        except Exception as e:
            return f"Lỗi khi phân tích OSI: {str(e)}"

    def _analyze_tcp_flags(self, results_param: Optional[Dict[str, Any]]) -> str:
        current_results = self._get_effective_results(results_param)
        if not current_results or not current_results.get("packets"):
            return "Không có dữ liệu gói tin để phân tích cờ TCP. Vui lòng tải lên file PCAP."
        try:
            tcp_packets = [p for p in current_results.get("packets", []) if hasattr(p, 'haslayer') and p.haslayer('TCP')]
            if not tcp_packets:
                return "Không tìm thấy gói tin TCP để phân tích cờ."
            return self.smolagent_gateway.tcp_flags_agent.run(tcp_packets=tcp_packets)
        except Exception as e:
            return f"Lỗi khi phân tích cờ TCP: {str(e)}"

    def _predict_network_issues(self, results_param: Optional[Dict[str, Any]]) -> str:
        current_results = self._get_effective_results(results_param)
        if not current_results or not current_results.get("packets"):
            return "Không có dữ liệu gói tin để dự đoán vấn đề mạng. Vui lòng tải lên file PCAP."
        try:
            return self.smolagent_gateway.prediction_agent.run(results_summary=str(current_results.get("summary", {})), packets_data=current_results.get("packets", []))
        except Exception as e:
            return f"Lỗi khi dự đoán vấn đề mạng: {str(e)}"

    def _analyze_dangerous_parameters(self, results_param: Optional[Dict[str, Any]]) -> str:
        current_results = self._get_effective_results(results_param)
        if not current_results or not current_results.get("packets"):
            return "Không có dữ liệu gói tin để phân tích thông số nguy hiểm. Vui lòng tải lên file PCAP."
        try:
            return self.smolagent_gateway.attack_agent.run(
                query="Phân tích các thông số nguy hiểm, payload độc hại, hoặc các dấu hiệu bất thường trong dữ liệu.",
                packets=current_results.get("packets", []),
                results_summary=str(current_results.get("summary", {}))
            )
        except Exception as e:
            return f"Lỗi khi phân tích thông số nguy hiểm: {str(e)}"

    def get_initial_chat_message(self, results_param: Optional[Dict[str, Any]], pcap_file_param: Optional[str] = None) -> str:
        self.set_latest_results(results_param)
        if pcap_file_param:
            self.set_latest_pcap_file(pcap_file_param)

        current_results = self._get_effective_results(results_param)

        if not current_results or not current_results.get("packets"):
            return "Chào mừng bạn đến với Trợ lý Phân tích Mạng! Hiện tại chưa có dữ liệu gói tin nào được tải lên. Vui lòng tải lên một file PCAP để bắt đầu."
        
        num_packets = len(current_results.get("packets", []))
        file_info = f"File PCAP \"{self.latest_pcap_file}\" đã được tải" if self.latest_pcap_file else "Dữ liệu PCAP đã được tải"
        
        summary_lines = [
            f"Chào mừng bạn đến với Trợ lý Phân tích Mạng!",
            f"{file_info} với {num_packets} gói tin."
        ]
        pcap_summary = current_results.get("summary", {})
        if pcap_summary.get("start_time") and pcap_summary.get("end_time"):
            summary_lines.append(f"Thời gian ghi: {pcap_summary['start_time']} đến {pcap_summary['end_time']}.")
        
        protocol_dist = current_results.get("protocol_distribution")
        if protocol_dist:
            common_protocols = sorted(protocol_dist.items(), key=lambda item: item[1], reverse=True)
            summary_lines.append(f"Các giao thức phổ biến: {', '.join([f'{p} ({c})' for p, c in common_protocols[:3]])}.")
        
        summary_lines.append("Bạn muốn tôi phân tích gì cụ thể không (ví dụ: 'phân tích TCP', 'dấu hiệu arp spoofing', 'thống kê HTTP')?")
        return "\n".join(summary_lines)
