import os
import time
import json
import uuid
from abc import ABC, abstractmethod
from dotenv import load_dotenv
from typing import List, Dict, Any, Callable

# Telemetry setup
from telemetry_setup import setup_telemetry, force_flush_traces

# OpenTelemetry for manual tracing
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode

# LiteLLM for model interactions
from litellm import completion_with_retries

import logging

# Set up logging
logging.basicConfig(level=logging.INFO,
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("llm-agent")

# Global tracer provider
tracer_provider = None
tracer = None

# =============================================
# LLM LAYER - Model abstraction and interfaces
# =============================================

class BaseLLM(ABC):
    """Abstract base class for language model implementations"""
    
    @abstractmethod
    def generate(self, messages: List[Dict[str, Any]], tools=None, **kwargs) -> Dict[str, Any]:
        """Generate a response from the language model"""
        pass

class LiteLLMModel(BaseLLM):
    """LiteLLM implementation of the BaseLLM interface"""
    
    def __init__(self, model_name: str, api_key: str, parameters: Dict[str, Any] = None):
        self.model_name = model_name
        self.api_key = api_key
        self.parameters = parameters or {
            "temperature": 0.7,
            "max_tokens": 1000,
            "max_retries": 3
        }
    
    def generate(self, messages: List[Dict[str, Any]], tools=None, **kwargs) -> Dict[str, Any]:
        with tracer.start_as_current_span("llm.generate") as span:
            span.set_attribute("llm.model", self.model_name)
            span.set_attribute("llm.messages_count", len(messages))
            
            try:
                all_params = {**self.parameters, **kwargs}
                
                # Make the API call using litellm
                response = completion_with_retries(
                    model=self.model_name,
                    messages=messages,
                    api_key=self.api_key,
                    tools=tools,
                    **all_params
                )
                
                span.set_status(Status(StatusCode.OK))
                return {
                    "content": response.choices[0].message.content,
                    "tool_calls": response.choices[0].message.tool_calls if hasattr(response.choices[0].message, "tool_calls") else None,
                    "usage": response.usage if hasattr(response, "usage") else {},
                    "model": response.model if hasattr(response, "model") else self.model_name,
                    "raw_response": response
                }
                
            except Exception as e:
                span.set_status(Status(StatusCode.ERROR, str(e)))
                span.record_exception(e)
                logger.error(f"Error in LLM generation: {e}")
                raise

# =============================================
# MEMORY - For storing conversation history
# =============================================

class Memory(ABC):
    """Abstract base class for memory implementations"""
    
    @abstractmethod
    def add(self, message: Dict[str, Any]) -> None:
        """Add a message to memory"""
        pass
    
    @abstractmethod
    def get(self) -> List[Dict[str, Any]]:
        """Get all messages from memory"""
        pass
    
    @abstractmethod
    def clear(self) -> None:
        """Clear all messages from memory"""
        pass

class ConversationMemory(Memory):
    """Simple implementation of Memory that stores messages in a list"""
    
    def __init__(self):
        self.messages = []
    
    def add(self, message: Dict[str, Any]) -> None:
        self.messages.append(message)
    
    def get(self) -> List[Dict[str, Any]]:
        return self.messages
    
    def clear(self) -> None:
        self.messages = []

# =============================================
# TOOLS - For performing actions
# =============================================

class Tool:
    def __init__(self, name: str, description: str, function: Callable, parameters: Dict = None, returns: str = None):
        self.name = name
        self.description = description
        self.function = function
        self.parameters = parameters or {}
        self.returns = returns or "Result of the tool execution"
    
    def to_dict(self):
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": self.parameters,
                    "required": list(self.parameters.keys())
                }
            }
        }

class DuckDuckGoSearchTool(Tool):
    def __init__(self):
        parameters = {
            "query": {
                "type": "string",
                "description": "The search query to look up information on the web"
            }
        }
        super().__init__(
            name="duck_duck_go_search",
            description="Search the web using DuckDuckGo to find information about a topic or answer a question.",
            function=self.search,
            parameters=parameters,
            returns="Search results from DuckDuckGo as formatted text"
        )
    
    def search(self, query: str) -> str:
        with tracer.start_as_current_span("tool.duckduckgo_search") as span:
            span.set_attribute("tool.name", "duck_duck_go_search")
            span.set_attribute("tool.query", query)
            logger.info(f"Searching DuckDuckGo for: {query}")
            # In a real implementation, you would use a DuckDuckGo API here
            result = f"Search results for '{query}' (simulated response)"
            span.set_attribute("tool.result.length", len(result))
            return result

class VisitWebpageTool(Tool):
    def __init__(self):
        parameters = {
            "url": {
                "type": "string",
                "description": "The complete URL of the webpage to visit (including https:// or http://)"
            }
        }
        super().__init__(
            name="visit_webpage",
            description="Visit a webpage and retrieve its content. Use this for getting information from a specific URL.",
            function=self.visit,
            parameters=parameters,
            returns="Content from the webpage as text"
        )
    
    def visit(self, url: str) -> str:
        with tracer.start_as_current_span("tool.visit_webpage") as span:
            span.set_attribute("tool.name", "visit_webpage")
            span.set_attribute("tool.url", url)
            logger.info(f"Visiting webpage: {url}")
            # In a real implementation, you would fetch the content of the URL here
            result = f"Content of webpage at {url} (simulated response)"
            span.set_attribute("tool.result.length", len(result))
            return result

# =============================================
# SPECIALIZED TOOLS - Network and code specific
# =============================================

class NetworkPacketAnalyzerTool(Tool):
    """Tool for analyzing network packets"""
    
    def __init__(self):
        parameters = {
            "packet_data": {
                "type": "string",
                "description": "Hexadecimal or raw packet data to analyze"
            },
            "protocol": {
                "type": "string",
                "description": "Network protocol to focus on (e.g., TCP, UDP, HTTP, DNS)",
                "enum": ["TCP", "UDP", "HTTP", "DNS", "ICMP", "ARP", "All"]
            }
        }
        super().__init__(
            name="analyze_network_packet",
            description="Analyze network packet data to provide insights about protocols, flags, and potential issues.",
            function=self.analyze,
            parameters=parameters,
            returns="Detailed analysis of the network packet"
        )
    
    def analyze(self, packet_data: str, protocol: str = "All") -> str:
        with tracer.start_as_current_span("tool.network_packet_analyzer") as span:
            span.set_attribute("tool.name", "analyze_network_packet")
            span.set_attribute("tool.protocol", protocol)
            
            logger.info(f"Analyzing packet data for protocol: {protocol}")
            # In a real implementation, you would use a packet analysis library here
            result = f"Analysis of {protocol} packet: [Simulated detailed packet analysis]"
            span.set_attribute("tool.result.length", len(result))
            return result

class CodeSecurityScannerTool(Tool):
    """Tool for scanning network code for security vulnerabilities"""
    
    def __init__(self):
        parameters = {
            "code": {
                "type": "string",
                "description": "Network-related code (C or Java) to scan for security issues"
            },
            "language": {
                "type": "string",
                "description": "Programming language of the code",
                "enum": ["C", "Java", "Python"]
            }
        }
        super().__init__(
            name="scan_code_security",
            description="Scan network code for security vulnerabilities and suggest improvements.",
            function=self.scan,
            parameters=parameters,
            returns="Security analysis of the code with recommendations"
        )
    
    def scan(self, code: str, language: str) -> str:
        with tracer.start_as_current_span("tool.code_security_scanner") as span:
            span.set_attribute("tool.name", "scan_code_security")
            span.set_attribute("tool.language", language)
            span.set_attribute("tool.code_length", len(code))
            
            logger.info(f"Scanning {language} code for security issues")
            # In a real implementation, you would use a code security scanner here
            result = f"Security analysis of {language} code: [Simulated security scan results]"
            span.set_attribute("tool.result.length", len(result))
            return result

class ProtocolDocumentationTool(Tool):
    """Tool for retrieving documentation about network protocols"""
    
    def __init__(self):
        parameters = {
            "protocol": {
                "type": "string",
                "description": "Network protocol name to get documentation for (e.g., TCP, HTTP, DNS)"
            }
        }
        super().__init__(
            name="get_protocol_documentation",
            description="Get detailed documentation about a specific network protocol including headers, flags, and common use cases.",
            function=self.get_documentation,
            parameters=parameters,
            returns="Detailed documentation about the requested network protocol"
        )
    
    def get_documentation(self, protocol: str) -> str:
        with tracer.start_as_current_span("tool.protocol_documentation") as span:
            span.set_attribute("tool.name", "get_protocol_documentation")
            span.set_attribute("tool.protocol", protocol)
            
            logger.info(f"Getting documentation for protocol: {protocol}")
            # In a real implementation, you would fetch actual documentation
            result = f"Documentation for {protocol}: [Simulated protocol documentation]"
            span.set_attribute("tool.result.length", len(result))
            return result

# =============================================
# CHAINS - For sequential operations
# =============================================

class Chain(ABC):
    """Abstract base class for chain implementations"""
    
    @abstractmethod
    def run(self, input_data: Any) -> Any:
        """Run the chain with the given input"""
        pass

class LLMChain(Chain):
    """Chain for simple LLM-based operations"""
    
    def __init__(self, llm: BaseLLM, prompt_template: str, output_key: str = "result"):
        self.llm = llm
        self.prompt_template = prompt_template
        self.output_key = output_key
    
    def run(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        with tracer.start_as_current_span("chain.llm_chain.run") as span:
            for k, v in input_data.items():
                if isinstance(v, str):
                    span.set_attribute(f"chain.input.{k}", v[:100])  # Truncate long values
            
            # Format the prompt template with input data
            try:
                formatted_prompt = self.prompt_template.format(**input_data)
                
                # Prepare messages for the LLM
                messages = [{"role": "user", "content": formatted_prompt}]
                
                # Generate response
                response = self.llm.generate(messages)
                
                # Return the response
                result = {self.output_key: response["content"]}
                span.set_attribute(f"chain.output.{self.output_key}", result[self.output_key][:100])
                return result
                
            except Exception as e:
                span.set_status(Status(StatusCode.ERROR, str(e)))
                span.record_exception(e)
                logger.error(f"Error in LLMChain: {e}")
                return {self.output_key: f"Error: {str(e)}"}

class SequentialChain(Chain):
    """Chain for running multiple chains in sequence"""
    
    def __init__(self, chains: List[Chain], input_variables: List[str], output_variables: List[str]):
        self.chains = chains
        self.input_variables = input_variables
        self.output_variables = output_variables
    
    def run(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        with tracer.start_as_current_span("chain.sequential_chain.run") as span:
            # Check if all required input variables are present
            for var in self.input_variables:
                if var not in input_data:
                    error_msg = f"Missing required input variable: {var}"
                    span.set_status(Status(StatusCode.ERROR, error_msg))
                    logger.error(error_msg)
                    return {"error": error_msg}
            
            # Run each chain in sequence
            current_data = input_data.copy()
            try:
                for i, chain in enumerate(self.chains):
                    result = chain.run(current_data)
                    current_data.update(result)
                    span.set_attribute(f"chain.step.{i}.output", str(result)[:100])
                
                # Extract only the requested output variables
                output = {key: current_data[key] for key in self.output_variables if key in current_data}
                return output
                
            except Exception as e:
                span.set_status(Status(StatusCode.ERROR, str(e)))
                span.record_exception(e)
                logger.error(f"Error in SequentialChain: {e}")
                return {"error": str(e)}

# Agent definitions
class Agent:
    def __init__(self, name: str, description: str, tools: List[Tool], llm: BaseLLM, memory: Memory):
        self.name = name
        self.description = description
        self.tools = tools
        self.llm = llm
        self.memory = memory
        self.id = str(uuid.uuid4())[:8]
    
    def add_message(self, role: str, content: str, tool_calls=None):
        message = {"role": role, "content": content}
        if tool_calls:
            message["tool_calls"] = tool_calls
        # Add tool_call_id if this is a tool message (required by Deepseek)
        if role == "tool" and tool_calls and len(tool_calls) > 0:
            message["tool_call_id"] = tool_calls[0]["id"]
        self.memory.add(message)
    
    def format_tools_for_api(self):
        return [tool.to_dict() for tool in self.tools]
    
    def run_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        with tracer.start_as_current_span(f"agent.run_tool.{tool_name}") as span:
            span.set_attribute("agent.name", self.name)
            span.set_attribute("agent.tool.name", tool_name)
            span.set_attribute("agent.tool.arguments", json.dumps(arguments))
            
            for tool in self.tools:
                if tool.name == tool_name:
                    try:
                        result = tool.function(**arguments)
                        span.set_status(Status(StatusCode.OK))
                        return {"result": result}
                    except Exception as e:
                        span.set_status(Status(StatusCode.ERROR, str(e)))
                        span.record_exception(e)
                        return {"error": str(e)}
            
            span.set_status(Status(StatusCode.ERROR, f"Tool {tool_name} not found"))
            return {"error": f"Tool {tool_name} not found"}
    
    def process_tool_calls(self, tool_calls):
        with tracer.start_as_current_span(f"agent.process_tool_calls") as span:
            span.set_attribute("agent.name", self.name)
            span.set_attribute("agent.tool_calls.count", len(tool_calls))
            
            results = []
            for tool_call in tool_calls:
                tool_call_id = tool_call["id"]
                tool_name = tool_call["function"]["name"]
                try:
                    arguments = json.loads(tool_call["function"]["arguments"])
                except json.JSONDecodeError:
                    arguments = {}
                
                logger.info(f"Running tool: {tool_name} with arguments: {arguments}")
                result = self.run_tool(tool_name, arguments)
                
                # Add the tool result as a message with the correct format for Deepseek
                self.add_message(
                    role="tool",
                    content=json.dumps(result),
                    tool_calls=[{
                        "id": tool_call_id,  # Use the original tool_call_id
                        "type": "function",
                        "function": {
                            "name": tool_name,
                            "arguments": tool_call["function"]["arguments"]
                        }
                    }]
                )
                results.append(result)
            return results
    
    def generate_response(self, query: str) -> str:
        with tracer.start_as_current_span(f"agent.generate_response") as span:
            span.set_attribute("agent.name", self.name)
            span.set_attribute("agent.query", query)
            
            # Add the user query to conversation history
            self.add_message("user", query)
            
            # Generate a response using the LLM
            try:
                logger.info(f"Generating response using {self.llm.model_name}")
                
                response = self.llm.generate(
                    messages=self.memory.get(),
                    tools=self.format_tools_for_api() if self.tools else None
                )
                
                # Check if the message has tool calls
                if response["tool_calls"]:
                    # Add attributes to the span
                    span.set_attribute("agent.response.has_tool_calls", True)
                    span.set_attribute("agent.response.tool_calls_count", len(response["tool_calls"]))
                    
                    # Add the assistant's response with tool calls
                    self.add_message(
                        "assistant", 
                        response["content"] or "", 
                        response["tool_calls"]
                    )
                    
                    # Execute the tool calls
                    tool_results = self.process_tool_calls(response["tool_calls"])
                    
                    # Generate another response with the tool results
                    return self.generate_response("Please continue based on the search results.")
                else:
                    # Add the assistant's response without tool calls
                    span.set_attribute("agent.response.has_tool_calls", False)
                    span.set_attribute("agent.response.content_length", len(response["content"]))
                    
                    self.add_message("assistant", response["content"])
                    return response["content"]
                
            except Exception as e:
                span.set_status(Status(StatusCode.ERROR, str(e)))
                span.record_exception(e)
                logger.error(f"Error generating response: {e}")
                return f"Error: {str(e)}"

class ManagerAgent(Agent):
    def __init__(self, name: str, description: str, tools: List[Tool], managed_agents: List[Agent], llm: BaseLLM, memory: Memory):
        super().__init__(name, description, tools, llm, memory)
        self.managed_agents = managed_agents
    
    def delegate_to_agent(self, agent_name: str, query: str) -> str:
        with tracer.start_as_current_span(f"manager.delegate") as span:
            span.set_attribute("manager.name", self.name)
            span.set_attribute("manager.target_agent", agent_name)
            span.set_attribute("manager.query", query)
            
            for agent in self.managed_agents:
                if agent.name == agent_name:
                    logger.info(f"Delegating to agent {agent_name}: {query}")
                    return agent.generate_response(query)
            
            span.set_status(Status(StatusCode.ERROR, f"Agent {agent_name} not found"))
            return f"Agent {agent_name} not found"
    
    def run(self, query: str) -> str:
        with tracer.start_as_current_span(f"manager.run") as span:
            span.set_attribute("manager.name", self.name)
            span.set_attribute("manager.query", query)
            
            # Setup system message for the manager
            system_message = f"""You are a manager agent that orchestrates other specialized agents.
You have the following agents available:
{', '.join([agent.name + ': ' + agent.description for agent in self.managed_agents])}

When appropriate, delegate tasks to these agents using their names.
For this specific query, determine which agent(s) would be most helpful and use them."""
            
            self.add_message("system", system_message)
            
            # Add custom tools for delegation with proper parameter specifications
            delegation_tools = []
            for agent in self.managed_agents:
                # Create a closure that will capture the correct agent name
                def make_delegation_function(agent_name):
                    return lambda query: self.delegate_to_agent(agent_name, query)
                
                # Create the delegation function for this specific agent
                delegation_function = make_delegation_function(agent.name)
                
                # Define parameters for the delegation tool
                parameters = {
                    "query": {
                        "type": "string",
                        "description": f"The query or task to delegate to the {agent.name}"
                    }
                }
                
                delegation_tools.append(Tool(
                    name=f"delegate_to_{agent.name}",
                    description=f"Delegate a task to the {agent.name} agent. {agent.description}",
                    function=delegation_function,
                    parameters=parameters,
                    returns="Response from the delegated agent"
                ))
            
            # Temporarily add delegation tools to the available tools
            original_tools = self.tools
            self.tools = delegation_tools
            
            response = self.generate_response(query)
            
            # Restore original tools
            self.tools = original_tools
            
            return response

# =============================================
# SPECIALIZED AGENTS
# =============================================

class NetworkAnalysisAgent(Agent):
    """Agent specialized in network analysis"""
    
    def __init__(self, name: str, description: str, tools: List[Tool], llm: BaseLLM, memory: Memory):
        super().__init__(name, description, tools, llm, memory)
        # Add system message to guide the agent's behavior
        self.add_message("system", """You are a network analysis specialist. 
Your job is to analyze network traffic, diagnose problems, and explain networking concepts.
Use your tools to examine network data, interpret protocols, and provide insights.
Always provide detailed explanations that would help a network engineer understand the underlying issues.""")

class CodeAnalysisAgent(Agent):
    """Agent specialized in code analysis"""
    
    def __init__(self, name: str, description: str, tools: List[Tool], llm: BaseLLM, memory: Memory):
        super().__init__(name, description, tools, llm, memory)
        # Add system message to guide the agent's behavior
        self.add_message("system", """You are a code analysis expert specializing in networking code.
Your job is to analyze, explain, and improve network-related code, especially in C and Java.
Focus on identifying bugs, security issues, and performance bottlenecks in networking code.
When suggesting improvements, provide concrete code examples.""")

class ProtocolExpertAgent(Agent):
    """Agent specialized in network protocols"""
    
    def __init__(self, name: str, description: str, tools: List[Tool], llm: BaseLLM, memory: Memory):
        super().__init__(name, description, tools, llm, memory)
        # Add system message to guide the agent's behavior
        self.add_message("system", """You are a network protocol expert with deep knowledge of TCP/IP, HTTP, DNS, and other protocols.
Your job is to explain how protocols work, analyze protocol-specific issues, and suggest protocol-level optimizations.
Always be thorough and precise in your explanations of protocol behavior, especially regarding edge cases and security concerns.""")

# Telemetry-instrumented entrypoint
def main():
    global tracer_provider, tracer
    
    # Initialize telemetry
    tracer_provider = setup_telemetry()
    tracer = trace.get_tracer("multi-agent-system", "1.0.0")
    
    with tracer.start_as_current_span("app.main") as main_span:
        # Load environment variables
        load_dotenv()
    
        # Get API key
        api_key = os.getenv("DEEPSEEK_API_KEY")
        if not api_key:
            main_span.set_status(Status(StatusCode.ERROR, "DEEPSEEK_API_KEY not set"))
            raise ValueError("DEEPSEEK_API_KEY environment variable not set")
    
        # Set API key for litellm
        os.environ["DEEPSEEK_API_KEY"] = api_key
    
        # Clear any potential conflicts
        for var in ["LITELLM_MODEL", "ANTHROPIC_API_KEY"]:
            if var in os.environ:
                del os.environ[var]
                logger.info(f"Removed {var} from environment")
    
        logger.info("Setting up LLM model with Deepseek...")
    
        # Configure model name
        model_name = "deepseek/deepseek-chat"
        logger.info(f"Using model: {model_name}")
        main_span.set_attribute("app.model_name", model_name)
    
        # Set up a web-searching agent with tools
        llm = LiteLLMModel(model_name=model_name, api_key=api_key)
        memory = ConversationMemory()
        search_agent = Agent(
            name="search_agent",
            description="This is an agent that can do web search.",
            tools=[DuckDuckGoSearchTool(), VisitWebpageTool()],
            llm=llm,
            memory=memory
        )
    
        # Specialized agents
        network_analysis_agent = NetworkAnalysisAgent(
            name="network_analysis_agent",
            description="This agent specializes in network analysis tasks.",
            tools=[NetworkPacketAnalyzerTool(), ProtocolDocumentationTool()],
            llm=llm,
            memory=ConversationMemory()
        )
        
        code_analysis_agent = CodeAnalysisAgent(
            name="code_analysis_agent",
            description="This agent specializes in analyzing and improving network-related code.",
            tools=[CodeSecurityScannerTool()],
            llm=llm,
            memory=ConversationMemory()
        )
        
        protocol_expert_agent = ProtocolExpertAgent(
            name="protocol_expert_agent",
            description="This agent specializes in explaining and analyzing network protocols.",
            tools=[ProtocolDocumentationTool()],
            llm=llm,
            memory=ConversationMemory()
        )
    
        # Manager agent orchestrates the specialized agents
        manager_memory = ConversationMemory()
        manager_agent = ManagerAgent(
            name="manager_agent",
            description="This is a manager agent that orchestrates other agents.",
            tools=[],
            managed_agents=[search_agent, network_analysis_agent, code_analysis_agent, protocol_expert_agent],
            llm=llm,
            memory=manager_memory
        )
    
        # Run the agent task
        with tracer.start_as_current_span("app.run_task") as task_span:
            task = "If the US keeps its 2024 growth rate, how many years will it take for the GDP to double?"
            task_span.set_attribute("app.task", task)
            
            logger.info("Running agent task...")
            response = manager_agent.run(task)
            
            task_span.set_attribute("app.response_length", len(response))
            logger.info(f"Final response: {response}")
    
    # Flush telemetry before exit
    force_flush_traces(tracer_provider)
    time.sleep(2)


if __name__ == "__main__":
    main()