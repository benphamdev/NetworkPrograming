# File added for protocol integration
"""
This temporary file is used to integrate protocol analysis functionality.
The methods defined here need to be added to the chat_handler.py file.
"""

def _detect_protocol_query(self, query: str) -> tuple:
    """
    Phát hiện các truy vấn liên quan đến giao thức cụ thể.
    
    Args:
        query: Truy vấn của người dùng
        
    Returns:
        Tuple (protocol, analysis_type) nếu phát hiện truy vấn giao thức, ngược lại (None, None)
    """
    query_lower = query.lower()
    
    # Các giao thức hỗ trợ
    protocols = {
        'tcp': ['tcp', 'giao thức tcp', 'gói tcp'],
        'udp': ['udp', 'giao thức udp', 'gói udp'],
        'icmp': ['icmp', 'giao thức icmp', 'gói icmp', 'ping'],
        'ip': ['ip', 'giao thức ip', 'gói ip', 'ipv4', 'ipv6'],
        'arp': ['arp', 'giao thức arp', 'gói arp'],
        'dns': ['dns', 'giao thức dns', 'gói dns', 'phân giải tên miền'],
        'http': ['http', 'giao thức http', 'gói http'],
        'https': ['https', 'giao thức https', 'gói https', 'tls', 'ssl'],
        'ethernet': ['ethernet', 'giao thức ethernet', 'gói ethernet', 'lớp liên kết']
    }
    
    # Các loại phân tích
    analysis_types = {
        'handshake': ['bắt tay', 'handshake', 'kết nối', 'thiết lập kết nối'],
        'flags': ['cờ', 'flags', 'tcp flags', 'trạng thái'],
        'header': ['header', 'tiêu đề', 'thông tin tiêu đề'],
        'payload': ['payload', 'dữ liệu', 'nội dung'],
        'error': ['lỗi', 'error', 'vấn đề', 'bất thường'],
        'statistics': ['thống kê', 'số liệu', 'tần suất', 'phân bố']
    }
    
    # Kiểm tra từng giao thức
    detected_protocol = None
    for protocol, keywords in protocols.items():
        for keyword in keywords:
            # Tìm kiếm chính xác các từ khóa giao thức
            pattern = r'\b' + re.escape(keyword) + r'\b'
            if re.search(pattern, query_lower):
                detected_protocol = protocol.upper()
                break
        if detected_protocol:
            break
            
    # Nếu không tìm thấy giao thức cụ thể, trả về None
    if not detected_protocol:
        return None, None
        
    # Kiểm tra loại phân tích
    detected_analysis_type = None
    for analysis_type, keywords in analysis_types.items():
        for keyword in keywords:
            pattern = r'\b' + re.escape(keyword) + r'\b'
            if re.search(pattern, query_lower):
                detected_analysis_type = analysis_type
                break
        if detected_analysis_type:
            break
            
    return detected_protocol, detected_analysis_type
    
def _analyze_protocol_query(self, protocol: str, analysis_type: str, results: Dict) -> str:
    """
    Phân tích truy vấn liên quan đến giao thức cụ thể.
    
    Args:
        protocol: Giao thức cần phân tích
        analysis_type: Loại phân tích (nếu có)
        results: Kết quả phân tích PCAP
        
    Returns:
        Phân tích về giao thức cụ thể
    """
    if not results or not results.get("packets"):
        return f"Không có dữ liệu gói tin để phân tích giao thức {protocol}. Vui lòng tải lên file PCAP."
        
    # Lấy danh sách gói tin từ kết quả
    packets = results.get("packets", [])
    
    # Thực hiện phân tích giao thức
    try:
        analysis_result = self.protocol_analyzer.analyze_protocol(protocol, packets, analysis_type)
        
        # Kiểm tra kết quả và trả về phân tích
        if isinstance(analysis_result, dict) and "analysis" in analysis_result:
            if analysis_result.get("status") == "no_data":
                return f"Không tìm thấy gói tin {protocol} trong dữ liệu đã phân tích."
                
            # Thêm tiêu đề và thông tin file
            file_name = os.path.basename(self.latest_pcap_file) if self.latest_pcap_file else "đã tải lên"
            header = f"# Phân tích giao thức {protocol}\n\n"
            header += f"*File: {file_name}*\n\n"
            
            # Thêm thông tin số lượng gói tin
            if "packet_count" in analysis_result:
                header += f"Phân tích dựa trên **{analysis_result['packet_count']}** gói tin {protocol}.\n\n"
                
            return header + analysis_result["analysis"]
        else:
            return f"Không thể phân tích giao thức {protocol}. Lỗi định dạng kết quả."
    except Exception as e:
        return f"Lỗi khi phân tích giao thức {protocol}: {str(e)}"

def _analyze_protocol_distribution(self, results: Dict) -> str:
    """
    Phân tích phân bố giao thức từ kết quả phân tích PCAP.
    
    Args:
        results: Kết quả phân tích PCAP
        
    Returns:
        Phân tích về phân bố giao thức
    """
    if not results or not results.get("packets"):
        return "Không có dữ liệu gói tin để phân tích phân bố giao thức. Vui lòng tải lên file PCAP."
        
    # Lấy danh sách gói tin từ kết quả
    packets = results.get("packets", [])
    
    # Thực hiện phân tích phân bố giao thức
    try:
        distribution_result = self.protocol_analyzer.analyze_protocol_distribution(packets)
        
        # Kiểm tra kết quả và trả về phân tích
        if isinstance(distribution_result, dict) and "analysis" in distribution_result:
            if distribution_result.get("status") == "no_data":
                return "Không thể xác định giao thức từ các gói tin."
                
            # Thêm tiêu đề và thông tin file
            file_name = os.path.basename(self.latest_pcap_file) if self.latest_pcap_file else "đã tải lên"
            header = f"# Phân tích phân bố giao thức\n\n"
            header += f"*File: {file_name}*\n\n"
            
            return header + distribution_result["analysis"]
        else:
            return "Không thể phân tích phân bố giao thức. Lỗi định dạng kết quả."
    except Exception as e:
        return f"Lỗi khi phân tích phân bố giao thức: {str(e)}"
