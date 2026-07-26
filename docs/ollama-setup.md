# Connecting mobsf-mcp to Ollama (Local LLM)

MCP is a protocol between an AI agent and tools. The MCP server (mobsf-mcp) provides the tools. You need an MCP **client** that connects to an LLM. Here are your options:

## Option 1: Open WebUI + mcpo (Recommended for Ollama)

[Open WebUI](https://github.com/open-webui/open-webui) has native MCP support via its "Tools" feature. It connects to Ollama and can use MCP tools.

```bash
# 1. Run mcpo (MCP-to-OpenAPI bridge) to expose the MCP server as HTTP
pip install mcpo
MOBSF_URL=http://localhost:8000 MOBSF_API_KEY=your_key mcpo --port 8080 -- mobsf-mcp

# 2. In Open WebUI settings, add the tool server:
#    URL: http://localhost:8080
#    Open WebUI will discover all 22 tools automatically.
```

## Option 2: Claude Desktop / Kiro CLI

Add to `~/.claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "mobsf": {
      "command": "mobsf-mcp",
      "env": {
        "MOBSF_URL": "http://localhost:8000",
        "MOBSF_API_KEY": "your_key_here"
      }
    }
  }
}
```

## Option 3: Custom Python Agent with Ollama

If you want a lightweight script that uses Ollama directly with MCP tools:

```python
#!/usr/bin/env python3
"""Minimal Ollama + MCP agent for Android pentesting."""

import asyncio
import json
import ollama
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

SYSTEM_PROMPT = """You are an Android security analyst. You have access to MobSF tools
for static and dynamic analysis of Android applications. When asked to analyze an APK:
1. Upload it with upload_apk
2. Scan it with scan_apk  
3. Get the scorecard with get_security_scorecard
4. Dive into specific findings with get_report
5. If needed, inspect source with view_source_file

Always explain findings in security context and suggest remediations."""

async def run_agent(user_message: str):
    server_params = StdioServerParameters(
        command='mobsf-mcp',
        env={
            'MOBSF_URL': 'http://localhost:8000',
            'MOBSF_API_KEY': 'your_key_here',
        },
    )
    
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            
            # Get available tools for Ollama
            tools_result = await session.list_tools()
            ollama_tools = []
            for tool in tools_result.tools:
                ollama_tools.append({
                    "type": "function",
                    "function": {
                        "name": tool.name,
                        "description": tool.description,
                        "parameters": tool.inputSchema,
                    }
                })
            
            messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_message},
            ]
            
            # Agent loop
            while True:
                response = ollama.chat(
                    model="llama3.1:8b",
                    messages=messages,
                    tools=ollama_tools,
                )
                
                msg = response["message"]
                messages.append(msg)
                
                if not msg.get("tool_calls"):
                    print(f"\nAgent: {msg['content']}")
                    break
                
                # Execute tool calls
                for tc in msg["tool_calls"]:
                    fn_name = tc["function"]["name"]
                    fn_args = tc["function"]["arguments"]
                    print(f"  [Tool] {fn_name}({json.dumps(fn_args)[:100]}...)")
                    
                    result = await session.call_tool(fn_name, fn_args)
                    tool_response = result.content[0].text
                    
                    messages.append({
                        "role": "tool",
                        "content": tool_response,
                    })

if __name__ == "__main__":
    import sys
    query = sys.argv[1] if len(sys.argv) > 1 else "Analyze /home/kali/labs/MCP/tests/test.apk"
    asyncio.run(run_agent(query))
```

## Option 4: Kiro CLI (this tool)

If you're running Kiro CLI with `/code init` and MCP configured, you can use it directly in conversation. The MCP tools will appear as available tools.

## Emulator Setup (for Dynamic Analysis)

Dynamic analysis features (Frida, logcat, activity testing, TLS tests) require an Android emulator connected to MobSF.

### Without Docker networking issues:

The simplest approach is to run MobSF **without Docker** for dynamic analysis:

```bash
# Install MobSF natively
git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git
cd Mobile-Security-Framework-MobSF
./setup.sh
./run.sh
```

Then connect your emulator (Genymotion or Android Studio AVD) - MobSF auto-detects via ADB.

### With Docker (static analysis only is fine):

If you only need static analysis (which covers 90% of security findings), Docker works perfectly. Dynamic analysis with Docker requires `network_mode: host` or complex ADB bridge setup.

```yaml
# docker-compose.yml for dynamic analysis support
services:
  mobsf:
    image: opensecurity/mobile-security-framework-mobsf:latest
    network_mode: host  # Required for ADB access to host emulator
    environment:
      - DJANGO_SUPERUSER_USERNAME=mobsf
      - DJANGO_SUPERUSER_PASSWORD=mobsf
```
