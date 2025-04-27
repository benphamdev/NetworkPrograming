| Python scripts     | Brief description                        |
| ------------------ | ---------------------------------------- |
| 01-simple.py       | Question-Answer                          |
| 02-workflow.py     | dummy_tool                               |
| 03-workflow.py     | GoogleCalendarTool                       |
| 04-workflow.py     | GoogleCalendarTool + GetWeatherTool      |
| 05-agent_1.py      | with toolcall                            |
| 06-agent-net.py    | with Network-related query (no tool)     |
| 07-sm-agent.py     | Smolagents using CodeAgent               |
| 08-net-sm-agent.py | Smolagents using CodeAgent with toolcall |
| 09-observation     | Trace llm and agent actions messages     |

usage:

using the command to run the server:

```bash
python -m phoenix.server.main serve

python -m phoenix.server.main serve --port 8080 --host

```

you can intstall the package using pip:

```bash
pip install netifaces
```

or if error you can directly download the package from the following link:
<https://dl.espressif.com/pypi/netifaces/>

and install it using pip:

```bash
pip install netifaces-0.10.9-cp312-cp312-win_amd64.whl
```
