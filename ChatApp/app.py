import os
from dotenv import load_dotenv

import streamlit as st

from ai_providers.factory import AIChatProviderFactory

# Load environment variables from .env file
load_dotenv()

def initialize_chat_provider():
    """Initialize the AI chat provider based on available API keys"""
    try:
        # Check for API keys in session state first (UI input)
        openai_key = st.session_state.get('openai_api_key', None) or os.getenv("OPEN_AI_API_KEY")
        groq_key = st.session_state.get('groq_api_key', None) or os.getenv("GROQ_API_KEY")
        gemini_key = st.session_state.get('gemini_api_key', None) or os.getenv("GEMINI_API_KEY")

        # Temporarily set environment variables for this session if provided via .env or UI
        if openai_key:
            os.environ['OPENAI_API_KEY'] = openai_key
        if groq_key:
            os.environ['GROQ_API_KEY'] = groq_key
        if gemini_key:
            os.environ['GEMINI_API_KEY'] = gemini_key

        # Try to use provider specified in the sidebar if it exists
        provider_type = st.session_state.get('provider_type', None)
        if provider_type:
            return AIChatProviderFactory.create_provider(provider_type)

        # Otherwise get the default provider based on available API keys
        return AIChatProviderFactory.get_default_provider()
    except ValueError as e:
        st.error(f"Error initializing AI provider: {str(e)}")
        st.info("Please check your .env file or set API keys in the sidebar below")
        return None

def clear_input():
    """Callback function to clear user input"""
    if "user_input" in st.session_state:
        st.session_state.user_input = ""

def main():
    # Set page configuration to wide mode for better layout
    st.set_page_config(page_title="AI Chat Application", layout="wide", initial_sidebar_state="expanded")

    # Apply custom CSS for better styling
    st.markdown("""
        <style>
            /* Make the chat container fill most of the screen */
            .main .block-container {
                padding-top: 2rem;
                padding-bottom: 6rem;  /* Space for fixed input area */
            }
        
            /* Style chat messages */
            .user-message {
                background-color: #e6f7ff;
                border-radius: 15px;
                padding: 10px 15px;
                margin: 5px 0;
                text-align: right;
                border: 1px solid #cce5ff;
            }
            .assistant-message {
                background-color: #f0f2f6;
                border-radius: 15px;
                padding: 10px 15px;
                margin: 5px 0;
                border: 1px solid #e0e0e0;
            }
        
            /* Fixed input container */
            .fixed-input-container {
                position: fixed;
                bottom: 0.5rem;  /* Push closer to the bottom edge */
                left: 0;
                right: 0;
                padding: 0.5rem 1rem;
                background-color: transparent;  /* Remove background for centering */
                z-index: 999;
                display: flex;
                justify-content: center;  /* Center the form */
                align-items: center;
                transition: all 0.3s ease-in-out;
                width: 100%;
                min-width: 300px;
            }
        
            /* Form container styling */
            .stForm {
                position: relative;
                background: white;
                border-radius: 50px;  /* Rounded corners like ChatGPT */
                box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);  /* Subtle shadow */
                width: 50%;  /* Adjusted width for better appearance */
                max-width: 700px;  /* Maximum width for larger screens */
                min-width: 400px;  /* Minimum width for smaller screens */
                padding: 5px 10px;  /* Padding inside the form */
                display: flex;
                align-items: center;
                transition: all 0.3s ease-in-out;
            }
        
            /* Target main content area */
            .main .stForm, 
            .main .fixed-input-container {
                width: 100%;
            }
        
            /* Adjust when sidebar is expanded */
            [data-testid="stSidebar"][aria-expanded="true"] ~ .main .fixed-input-container {
                left: 21rem;
                width: calc(100% - 21rem);  /* Shrink width when sidebar is open */
                justify-content: center;  /* Ensure centering even when sidebar is open */
            }
        
            /* Adjust when sidebar is collapsed */
            [data-testid="stSidebar"][aria-expanded="false"] ~ .main .fixed-input-container {
                left: 0;
                width: 100%;
                justify-content: center;  /* Center when sidebar is collapsed */
            }
        
            /* Add padding to main content to prevent overlap */
            .main .block-container {
                padding-bottom: 100px !important;  /* Adjusted to ensure input field doesn't overlap content */
            }
        
            /* Style input field */
            .stTextInput input {
                border-radius: 50px !important;  /* Match the form's border radius */
                border: none !important;  /* Remove default border */
                padding: 10px 40px 10px 40px !important;  /* Padding for icons */
                font-size: 16px !important;
                background-color: transparent !important;
                outline: none !important;
                box-shadow: none !important;
            }
        
            /* Style placeholder text */
            .stTextInput input::placeholder {
                color: #888 !important;
                font-style: italic !important;
            }
        
            /* Style the Send button */
            .stButton button {
                border-radius: 50px;
                background-color: #007bff;  /* Blue button color */
                color: white;
                padding: 8px 20px;
                font-size: 14px;
                border: none;
                transition: background-color 0.3s ease;
            }
            .stButton button:hover {
                background-color: #0056b3;  /* Darker blue on hover */
            }
        
            /* Icon styling */
            .input-icon-left, .input-icon-right {
                position: absolute;
                top: 50%;
                transform: translateY(-50%);
                font-size: 20px;
                color: #888;
                cursor: pointer;
            }
            .input-icon-left {
                left: 15px;
            }
            .input-icon-right {
                right: 15px;
            }
        
            /* Ensure the form contents are properly aligned */
            .stForm > div {
                display: flex;
                align-items: center;
                width: 100%;
            }
        
            /* Hide default Streamlit footer */
            footer {
                visibility: hidden;
            }
        </style>
    """, unsafe_allow_html=True)

    # Initialize session state variables at the top
    if "input_value" not in st.session_state:
        st.session_state.input_value = ""
    if "messages" not in st.session_state:
        st.session_state.messages = []

    st.title("AI Chat Application")

    # Sidebar for provider selection
    st.sidebar.title("Settings")
    provider_options = ["Auto Detect", "OpenAI", "Groq", "Gemini"]
    selected_provider = st.sidebar.selectbox(
        "Select AI Provider",
        provider_options,
        index=0
    )
    with st.sidebar.expander("API Key Settings", expanded=False):
        st.markdown("### API Keys")
        openai_key = st.text_input("OpenAI API Key", type="password",
                                   value=st.session_state.get('openai_api_key', ''))
        groq_key = st.text_input("Groq API Key", type="password",
                                 value=st.session_state.get('groq_api_key', ''))
        gemini_key = st.text_input("Gemini API Key", type="password",
                                   value=st.session_state.get('gemini_api_key', ''))
        if openai_key:
            st.session_state.openai_api_key = openai_key
        if groq_key:
            st.session_state.groq_api_key = groq_key
        if gemini_key:
            st.session_state.gemini_api_key = gemini_key

    # Update provider logic
    if (openai_key and openai_key != os.environ.get('OPENAI_API_KEY', '')) or \
            (groq_key and groq_key != os.environ.get('GROQ_API_KEY', '')) or \
            (gemini_key and gemini_key != os.environ.get('GEMINI_API_KEY', '')):
        if 'provider' in st.session_state:
            del st.session_state.provider
    if selected_provider != "Auto Detect":
        st.session_state.provider_type = selected_provider.lower()
        if selected_provider.lower() == "gemini":
            os.environ["GEMINI_MODEL"] = "gemini-2.0-flash"
        if 'provider' in st.session_state:
            del st.session_state.provider
    elif 'provider_type' in st.session_state:
        del st.session_state.provider_type
    if 'provider' not in st.session_state:
        st.session_state.provider = initialize_chat_provider()
    if st.session_state.provider:
        info = st.session_state.provider.get_model_info()
        st.sidebar.markdown(f"### Using {info['provider']} - {info['model']}")

    # Main chat area with scrolling container
    chat_container = st.container()

    # Create a fixed layout with proper spacing
    chat_display = chat_container.container()

    # Display chat history with styled messages
    with chat_display:
        for message in st.session_state.messages:
            if message["role"] == "user":
                st.markdown(f"<div class='user-message'><b>You:</b> {message['content']}</div>", unsafe_allow_html=True)
            else:
                st.markdown(f"<div class='assistant-message'><b>Assistant:</b> {message['content']}</div>", unsafe_allow_html=True)

        # Add empty space to ensure new messages are visible when input is fixed
        st.markdown("<div style='height: 100px'></div>", unsafe_allow_html=True)

    # Create a placeholder for responses above the input
    response_placeholder = st.empty()

    # Create a fixed input container at the bottom using st.form for Enter submission
    fixed_input_container = st.container()

    with fixed_input_container:
        with st.form(key="chat_form", clear_on_submit=True):
            st.markdown("<div class='fixed-input-container'>", unsafe_allow_html=True)
            st.markdown("<div class='stForm'>", unsafe_allow_html=True)  # Wrap the form in stForm class

            # Create a layout with columns for icons, input, and send button
            col_icon_left, col_input, col_icon_right, col_send = st.columns([1, 8, 1, 2])

            with col_icon_left:
                st.markdown("<div class='input-icon-left'>➕</div>", unsafe_allow_html=True)  # Plus icon

            with col_input:
                user_input = st.text_input("",
                                           placeholder="Ask anything",
                                           key="user_input",
                                           label_visibility="collapsed")

            with col_icon_right:
                st.markdown("<div class='input-icon-right'>🎙️</div>", unsafe_allow_html=True)  # Microphone icon

            with col_send:
                submit = st.form_submit_button("Send", use_container_width=True)  # Enable the Send button

            st.markdown("</div>", unsafe_allow_html=True)  # Close stForm div
            st.markdown("</div>", unsafe_allow_html=True)  # Close fixed-input-container div

    # Process input when form is submitted (via Send button or Enter key)
    if user_input and (submit or st.session_state.get("chat_form_submitted", False)):
        current_input = user_input
        st.session_state.messages.append({"role": "user", "content": current_input})

        # Get AI response
        if st.session_state.provider:
            full_response = ""
            try:
                with response_placeholder:
                    with st.spinner("Thinking..."):
                        for response_chunk in st.session_state.provider.stream_chat(
                                current_input,
                                [{"role": m["role"], "content": m["content"]}
                                 for m in st.session_state.messages[:-1]]
                        ):
                            if response_chunk:
                                full_response += response_chunk
                                st.markdown(f"<div class='assistant-message'><b>Assistant:</b> {full_response}▌</div>",
                                            unsafe_allow_html=True)
                    if full_response:
                        st.session_state.messages.append({"role": "assistant", "content": full_response})
                    else:
                        fallback_response = "I couldn't generate a response. Please try again."
                        st.session_state.messages.append({"role": "assistant", "content": fallback_response})
            except Exception as e:
                error_message = f"Error generating response: {str(e)}"
                st.session_state.messages.append({"role": "assistant", "content": error_message})
        else:
            st.session_state.messages.append({"role": "assistant",
                                              "content": "I'm not connected to an AI provider yet. Please enter your API keys in the sidebar."})

        st.session_state.chat_form_submitted = False  # Reset the form submission flag
        st.rerun()

    # Clear chat button in sidebar
    if st.sidebar.button("Clear Chat"):
        st.session_state.messages = []
        st.session_state.input_value = ""
        st.rerun()

if __name__ == "__main__":
    main()