"""
Snyk agent: one specialist in the DevSecOps team.

Job: run Snyk scans (code + dependencies) on a project and return a clean report.
It is built as its own small graph so a supervisor agent can call it later.
"""

import os

from langchain_core.messages import SystemMessage
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.graph import START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode, tools_condition

# Snyk's MCP server ships with 10+ tools. We only give this agent the ones it needs.
# Fewer tools = less confusion for the LLM and fewer tokens used.
ALLOWED_SNYK_TOOLS = {"snyk_trust", "snyk_code_scan", "snyk_sca_scan"}

# Scan results can be very long. The free GitHub Models tier has small input limits,
# so we cut very long tool outputs down to this many characters.
MAX_TOOL_OUTPUT = 8000

SNYK_MCP_SERVER = {
    "snyk": {
        "command": "npx",
        "args": ["-y", "snyk@latest", "mcp", "-t", "stdio"],
        "transport": "stdio",
        "env": dict(os.environ),  # passes SNYK_TOKEN (and PATH) to the Snyk CLI
    }
}

SYSTEM_PROMPT = """You are the Snyk agent in a DevSecOps team.
Your only job is to run Snyk scans on one project and report what Snyk finds.

Steps:
1. Call snyk_trust on the project folder (the absolute path is in the user's message).
2. Run snyk_code_scan on that folder (security issues in the code).
3. Run snyk_sca_scan on that folder (known vulnerabilities in dependencies).
4. For code issues, you may use read_file to look at the code around the finding.

Then write the report, highest severity first. For each finding give:
  Type: Code or Dependency
  Where: file and line (code) or package and version (dependency)
  Severity: Critical / High / Medium / Low
  Problem: one simple sentence
  Fix: one simple sentence (for dependencies, the version to upgrade to)

Rules:
- Only report what Snyk actually returned. Do not add your own guesses.
- If a scan fails, say which scan failed and the error message, then continue with the other.
- End with one line: total findings by severity."""


async def load_snyk_tools():
    """Start the Snyk MCP server and return only the tools we allow."""
    client = MultiServerMCPClient(SNYK_MCP_SERVER)
    tools = await client.get_tools()
    return [t for t in tools if t.name in ALLOWED_SNYK_TOOLS]


def _shorten(message):
    """Cut very long tool results so they fit in the LLM's input limit."""
    text = message.content if isinstance(message.content, str) else str(message.content)
    if len(text) > MAX_TOOL_OUTPUT:
        text = text[:MAX_TOOL_OUTPUT] + "\n...[output cut short]"
    message.content = text
    return message


def build_snyk_agent(llm, tools):
    """Build the agent <-> tools loop, same shape as our first agent."""
    llm_with_tools = llm.bind_tools(tools)
    tool_runner = ToolNode(tools, handle_tool_errors=True)  # tool errors go back to the LLM

    async def agent_node(state: MessagesState):
        messages = [SystemMessage(SYSTEM_PROMPT)] + state["messages"]
        return {"messages": [await llm_with_tools.ainvoke(messages)]}

    async def tools_node(state: MessagesState):
        result = await tool_runner.ainvoke(state)
        return {"messages": [_shorten(m) for m in result["messages"]]}

    builder = StateGraph(MessagesState)
    builder.add_node("agent", agent_node)
    builder.add_node("tools", tools_node)
    builder.add_edge(START, "agent")
    builder.add_conditional_edges("agent", tools_condition)
    builder.add_edge("tools", "agent")
    return builder.compile(name="snyk_agent")