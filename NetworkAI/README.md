# Network AI Security Analyzer

This project enhances network security analysis by integrating OpenAI's API to provide AI-powered insights into network logs and security events.

## Features

- **AI-Powered Log Analysis**: Get AI insights on network security logs
- **Failure Explanation**: Get detailed explanations of specific failure messages
- **Attack Pattern Detection**: Identify potential attack patterns in network traffic
- **Interactive UI**: User-friendly interface for analyzing network logs

## Setup

1. Install requirements:

   ```
   pip install -r requirements.txt
   ```

2. Set up your OpenAI API key in the `.env` file:

   ```
   OPEN_AI_API_KEY=your_api_key_here
   ```

## Usage

### Command Line Interface

```python
from ai_analyzer import NetworkAIAnalyzer
import pandas as pd

# Initialize the analyzer
analyzer = NetworkAIAnalyzer()

# Load your log file
logs_df = pd.read_csv("path/to/your/logs.csv")

# Analyze logs
analysis = analyzer.analyze_logs(logs_df)
print(analysis['analysis'])

# Explain a specific failure reason
explanation = analyzer.explain_failure_reason("your failure reason here")
print(explanation['explanation'])

# Identify attack patterns
patterns = analyzer.identify_attack_patterns(logs_df)
print(patterns['attack_analysis'])
```

### Graphical Interface

Run the interactive analyzer:

```
python interactive_analyzer.py
```

## Demo

To try out the tool with sample data:

1. Run `python ai_analyzer.py` to test with the existing analyzer.csv file
2. Or load your own log files through the interactive interface by running `python interactive_analyzer.py`

## Note

This tool uses the OpenAI API, which has usage costs. The sample size parameter helps control API usage by limiting the number of log entries sent for analysis.

### References

- [OpenAI API Documentation](https://platform.openai.com/docs/guides/error-codes/api-errors)
- [Pandas Documentation](https://pandas.pydata.org/docs/)
- [Streamlit Documentation](https://docs.streamlit.io/library/get-started)
- [Python](https://www.askpython.com/python/examples/import-py-files-google-colab)
- [Import Python Project To Colob](https://saturncloud.io/blog/importing-py-files-in-google-colab/)
- [Import Python Project To Colob](https://stackoverflow.com/questions/48905127/importing-py-files-in-google-colab)
