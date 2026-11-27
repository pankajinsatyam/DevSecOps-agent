"""
Trivy agent: one specialist in the DevSecOps team.

Job: run Trivy on one target and return a clean report. The target can be:
  - a folder           -> vulnerabilities, misconfigurations (Dockerfile, Terraform, K8s) and secrets
  - a container image  -> vulnerabilities in the OS and the packages inside the image
  - a git repo URL     -> same as a folder, without cloning it first
  - an SBOM file       -> known vulnerabilities in the packages the SBOM lists

It has the same agent <-> tools loop as the Snyk agent, so a supervisor agent can call it later.
"""

import json
import shutil
import subprocess
from contextlib import asynccontextmanager
from pathlib import Path

from langchain_core.messages import SystemMessage
from langchain_core.tools import tool
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_mcp_adapters.tools import load_mcp_tools
from langgraph.graph import START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode, tools_condition

# Tools we take from Trivy's MCP server. findings_list reads the results of a scan.
ALLOWED_TRIVY_TOOLS = {"scan_filesystem", "scan_image", "scan_repository", "findings_list"}

# Same limit as the Snyk agent: cut very long tool outputs so they fit the LLM's input limit.
MAX_TOOL_OUTPUT = 8000

# Fields in a finding that are long and not needed for our report. We drop them to save space.
DROP_FIELDS = {"desc", "refs", "cwe", "cvss_vec", "epss_score", "epss_pct", "epss_date",
               "dep_path", "pkg_roots", "pub_date", "mod_date", "purl", "i"}

# One-time setup:  trivy plugin install mcp
TRIVY_MCP_SERVER = {
    "trivy": {
        "command": "trivy",
        "args": ["mcp", "--transport", "stdio"],
        "transport": "stdio",
    }
}

SYSTEM_PROMPT = """You are the Trivy agent in a DevSecOps team.
Your only job is to run Trivy on one target and report what Trivy finds.
The user's message says what the target is and which kind it is.

Which tool to use:
- folder         -> scan_filesystem with scanType ["vuln", "misconfig", "secret"]
- container image -> scan_image with scanType ["vuln", "secret"]
- git repo URL   -> scan_repository with scanType ["vuln", "misconfig", "secret"]
- SBOM file      -> scan_sbom (it takes no input and already knows the file)

For scan_filesystem, scan_image and scan_repository always pass:
  target = the exact target from the user's message
  targetType = "filesystem", "image" or "repository"
  severities = ["CRITICAL", "HIGH"]
  outputFormat = "json"
These scans only return a batch_id and counts. Then call findings_list with
  batchID = that batch_id, minSeverity = "HIGH",
  categories = the same list you used as scanType, limit = 30
If the reply has a next_token, you may call findings_list once more with token = next_token.
For folders, you may use read_file to look at a file around a misconfiguration.

How to read a finding from findings_list:
  c  = category: 0 Vulnerability, 1 Misconfiguration, 2 License, 3 Secret
  s  = severity: 4 Critical, 3 High, 2 Medium, 1 Low, 0 Unknown
  id = CVE or rule ID, an = package or resource name, av = installed version
  ap = target or path, f / ln = file and line, fv = fixed version, fc = fix command

Then write the report, highest severity first. For each finding give:
  Type: Vulnerability / Misconfiguration / Secret / License
  Where: package and version, or file and line
  ID: the CVE or rule ID
  Severity: Critical / High / Medium / Low
  Problem: one simple sentence
  Fix: one simple sentence (for packages, the version to upgrade to)

Rules:
- Only report what Trivy actually returned. Do not add your own guesses.
- If the same ID shows up for many packages in one image, you may group them in one line.
- If a tool fails, say which one failed and the error message.
- End with one line: total findings by severity (use the counts from the scan result)."""


@asynccontextmanager
async def trivy_tools():
    """Start the Trivy MCP server and keep ONE session open for the whole agent run.

    Why one session: a Trivy scan keeps its findings in the server's memory and only
    returns a batch_id. findings_list must then talk to the SAME server to read them.
    client.get_tools() (which the Snyk agent uses) starts a new server for every call,
    so the findings would be gone. Usage:

        async with trivy_tools() as tools:
            ...build and run the agent here...
    """
    client = MultiServerMCPClient(TRIVY_MCP_SERVER)
    async with client.session("trivy") as session:
        tools = await load_mcp_tools(session)
        yield [t for t in tools if t.name in ALLOWED_TRIVY_TOOLS]


def make_scan_sbom(sbom_file: Path):
    """Create a scan_sbom tool that can only scan this one SBOM file.

    Trivy's MCP server has no SBOM tool, so we run `trivy sbom` ourselves.
    The tool takes no input, so the LLM cannot point it at any other file.
    """

    @tool
    def scan_sbom() -> str:
        """Scan the SBOM file from the user's message for known vulnerabilities (CRITICAL and HIGH)."""
        if shutil.which("trivy") is None:
            return "Error: trivy is not installed or not on PATH."
        cmd = ["trivy", "sbom", "--format", "json", "--scanners", "vuln",
               "--severity", "CRITICAL,HIGH", "--quiet", str(sbom_file)]
        try:
            done = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        except subprocess.TimeoutExpired:
            return "Error: trivy sbom took longer than 10 minutes."
        if done.returncode != 0:
            return f"Error: trivy sbom failed: {done.stderr.strip()[-1500:]}"
        return summarize_sbom_report(done.stdout)

    return scan_sbom


def summarize_sbom_report(report_json: str, max_findings: int = 40) -> str:
    """Turn Trivy's big JSON report into a short list the LLM can read."""
    try:
        report = json.loads(report_json)
    except json.JSONDecodeError:
        return "Error: could not read Trivy's output as JSON."

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    findings, counts = [], {}
    for result in report.get("Results") or []:
        for v in result.get("Vulnerabilities") or []:
            sev = v.get("Severity", "UNKNOWN")
            counts[sev] = counts.get(sev, 0) + 1
            findings.append({
                "id": v.get("VulnerabilityID"),
                "package": v.get("PkgName"),
                "installed": v.get("InstalledVersion"),
                "fixed": v.get("FixedVersion") or "no fix yet",
                "severity": sev,
                "title": (v.get("Title") or "")[:150],
            })

    findings.sort(key=lambda f: order.get(f["severity"], 9))
    summary = {
        "sbom": report.get("ArtifactName"),
        "counts": counts,
        "findings": findings[:max_findings],
    }
    if len(findings) > max_findings:
        summary["note"] = f"Showing the top {max_findings} of {len(findings)} findings."
    return json.dumps(summary, indent=1)


def compact_findings(text: str) -> str:
    """Drop long fields and Trivy's help notes from a findings_list reply, so more findings fit."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return text
    if not isinstance(data, dict):
        return text
    data.pop("meta", None)
    for finding in data.get("findings") or []:
        for field in DROP_FIELDS:
            finding.pop(field, None)
    return json.dumps(data, separators=(",", ":"))


def _text_of(content) -> str:
    """MCP tool results come as a list of blocks. Join their text into one string."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = [b.get("text", "") if isinstance(b, dict) else str(b) for b in content]
        return "\n".join(parts)
    return str(content)


def _clean(message):
    """Make tool results short and readable for the LLM."""
    text = _text_of(message.content)
    if getattr(message, "name", None) == "findings_list":
        text = compact_findings(text)
    if len(text) > MAX_TOOL_OUTPUT:
        text = text[:MAX_TOOL_OUTPUT] + "\n...[output cut short]"
    message.content = text
    return message


def build_trivy_agent(llm, tools):
    """Build the agent <-> tools loop, same shape as the Snyk agent."""
    llm_with_tools = llm.bind_tools(tools)
    tool_runner = ToolNode(tools, handle_tool_errors=True)  # tool errors go back to the LLM

    async def agent_node(state: MessagesState):
        messages = [SystemMessage(SYSTEM_PROMPT)] + state["messages"]
        return {"messages": [await llm_with_tools.ainvoke(messages)]}

    async def tools_node(state: MessagesState):
        result = await tool_runner.ainvoke(state)
        return {"messages": [_clean(m) for m in result["messages"]]}

    builder = StateGraph(MessagesState)
    builder.add_node("agent", agent_node)
    builder.add_node("tools", tools_node)
    builder.add_edge(START, "agent")
    builder.add_conditional_edges("agent", tools_condition)
    builder.add_edge("tools", "agent")
    return builder.compile(name="trivy_agent")
