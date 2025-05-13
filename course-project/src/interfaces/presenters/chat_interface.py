"""
Chat Interface - Xử lý tương tác chat với người dùng.
"""
import os

class ChatInterface:
    """Xử lý giao diện chat và tương tác với người dùng."""

    def __init__(self, base_presenter, analyzer):
        """
        Khởi tạo Chat Interface.
        
        Args:
            base_presenter: BasePresenter instance
            analyzer: AnalyzerComponent instance
        """
        self.base_presenter = base_presenter
        self.analyzer = analyzer

    def process_chat_query(self, query: str) -> str:
        """
        Xử lý truy vấn chat và trả về phản hồi dựa trên file PCAP đã tải lên.
        
        Args:
            query: Truy vấn người dùng
            
        Returns:
            Phản hồi từ AI dựa trên phân tích file PCAP
        """
        # Kiểm tra có file và kết quả chưa
        has_file = self.base_presenter.latest_pcap_file is not None
        has_results = self.base_presenter.latest_results is not None

        if not has_file:
            return "Vui lòng tải lên file PCAP trước khi chat. Tôi cần dữ liệu từ file để phân tích và tư vấn."

        if not has_results:
            file_name = os.path.basename(self.base_presenter.latest_pcap_file)
            return f"Tôi đã nhận file {file_name} nhưng chưa được phân tích. Vui lòng nhấn nút 'Phân tích' trong tab 'Phân tích PCAP' và quay lại đây để tư vấn."

        # Log thông tin để debug
        pcap_file = self.base_presenter.latest_pcap_file
        pcap_info = f"(File đang phân tích: {pcap_file})" if pcap_file else "(Không có file)"

        # Sử dụng phương thức create_ai_chat_response từ AnalyzerComponent với context từ file
        response = self.analyzer.create_ai_chat_response(query, self.base_presenter.latest_results)

        return response

    def update_chat(self, user_message, chat_history):
        """
        Cập nhật lịch sử chat với truy vấn mới của người dùng, sử dụng context từ file PCAP.
        
        Args:
            user_message: Truy vấn của người dùng
            chat_history: Lịch sử chat hiện tại trong định dạng Gradio
            
        Returns:
            Cặp (truy vấn đã xóa, lịch sử chat đã cập nhật)
        """
        if not user_message:
            return "", chat_history

        # Kiểm tra có file và kết quả chưa
        has_file = self.base_presenter.latest_pcap_file is not None
        has_results = self.base_presenter.latest_results is not None

        if not has_file:
            bot_response = "Vui lòng tải lên file PCAP trước khi chat. Tôi cần phân tích file để cung cấp tư vấn chính xác về rủi ro mạng."
            chat_history.append({"role": "user", "content": user_message})
            chat_history.append({"role": "assistant", "content": bot_response})
            return "", chat_history

        if not has_results:
            file_name = os.path.basename(self.base_presenter.latest_pcap_file)
            bot_response = f"Tôi đã nhận file {file_name} nhưng chưa được phân tích. Vui lòng nhấn nút 'Phân tích' trong tab 'Phân tích PCAP' và quay lại đây để tư vấn."
            chat_history.append({"role": "user", "content": user_message})
            chat_history.append({"role": "assistant", "content": bot_response})
            return "", chat_history

        # Tạo phản hồi từ AI dựa trên context từ file PCAP
        bot_response = self.process_chat_query(user_message)

        # Thêm vào lịch sử chat ở định dạng Gradio messages
        chat_history.append({"role": "user", "content": user_message})
        chat_history.append({"role": "assistant", "content": bot_response})

        # Đồng thời cập nhật lịch sử chat trong analyzer để lưu trữ toàn bộ cuộc hội thoại
        self.analyzer.update_chat_history(user_message, self.base_presenter.latest_results)

        # Xóa truy vấn và trả về lịch sử đã cập nhật
        return "", chat_history

    def clear_chat(self):
        """
        Xóa lịch sử chat.
        
        Returns:
            Tuple (lịch sử chat trống, truy vấn trống)
        """
        # Đặt lại lịch sử chat trong analyzer
        self.analyzer.chat_history = []

        # Nếu có kết quả phân tích, thêm tin nhắn chào mừng mới
        if self.base_presenter.latest_results:
            initial_message = self.analyzer.get_initial_chat_message(self.base_presenter.latest_results)
            self.analyzer.chat_history = [{"role": "assistant", "content": initial_message}]
            # Trả về phiên bản định dạng gradio của tin nhắn chào mừng
            return [{"role": "assistant", "content": initial_message}], ""

        # Nếu không có kết quả phân tích, trả về lịch sử trống
        return [], ""

    def init_chat_on_upload(self, file):
        """
        Khởi tạo chat khi một file được tải lên
        
        Args:
            file: File PCAP được tải lên
            
        Returns:
            Lịch sử chat khởi tạo
        """
        if file:
            # Phân tích sơ qua file để cập nhật self.base_presenter.latest_pcap_file
            file_path = file.name if hasattr(file, 'name') else file
            self.base_presenter.latest_pcap_file = file_path
            # Trả về placeholder message trước khi phân tích
            return [{"role": "assistant",
                     "content": f"Đã nhận file {os.path.basename(file_path)}. Nhấn nút 'Phân tích' để tiến hành phân tích file."}]
        return [{"role": "assistant",
                 "content": "Chào bạn! Tôi là trợ lý phân tích mạng. Vui lòng tải lên file PCAP để bắt đầu phân tích."}]
