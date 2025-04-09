# Streamlit Chat Application

This is a simple chat application built using Streamlit. The application allows users to send messages and receive responses in real-time. It does not store any chat history, making it a lightweight solution for quick conversations.

## Project Structure

```
streamlit-chat-app/
├── app.py                      # Entry point (slim controller)
├── config/                     # Configuration management
│   ├── __init__.py
│   └── settings.py             # Environment and app settings
├── ui/                         # UI components
│   ├── __init__.py
│   ├── chat_view.py            # Chat display component
│   ├── sidebar.py              # Sidebar component
│   └── styles.py               # CSS styling
├── services/                   # Business logic
│   ├── __init__.py
│   └── chat_service.py         # Chat handling logic
├── ai_providers/               # AI provider implementations (existing)
└── utils/                      # Utility functions (existing)
```

## Requirements

To run this application, you need to install the required dependencies. You can do this by running:

```
pip install -r requirements.txt
```

## Running the Application

To start the Streamlit application, navigate to the project directory and run:

```
streamlit run app.py
```

This will launch the application in your default web browser.

## Features

- Simple user interface for chatting
- Real-time message sending and receiving
- No memory of past conversations

## Contributing

Feel free to fork the repository and submit pull requests for any improvements or features you would like to add.