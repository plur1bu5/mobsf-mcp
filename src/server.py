"""MobSF MCP Server - Agentic Android Security Analysis.

This MCP server exposes MobSF capabilities as tools that any
MCP-compatible AI agent can use to perform Android app security analysis.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from .mobsf_client import MobSFClient

# ──────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────

MOBSF_URL = os.environ.get("MOBSF_URL", "http://localhost:8000")
MOBSF_API_KEY = os.environ.get("MOBSF_API_KEY", "")

# Initialize MCP server
mcp = FastMCP(
    "mobsf-mcp",
    instructions="Android security analysis powered by MobSF. "
    "Provides static analysis, dynamic analysis, and Frida instrumentation "
    "for Android APKs through the Model Context Protocol.",
)

# Global client instance (lazy init)
_client: MobSFClient | None = None


def get_client() -> MobSFClient:
    global _client
    if _client is None:
        if not MOBSF_API_KEY:
            raise RuntimeError(
                "MOBSF_API_KEY environment variable is not set. "
                "Get it from MobSF web UI (API Key in the REST API page)."
            )
        _client = MobSFClient(base_url=MOBSF_URL, api_key=MOBSF_API_KEY)
    return _client


def _truncate_report(report: dict, max_items: int = 20) -> dict:
    """Truncate large report sections to avoid overwhelming context."""
    truncated = {}
    for key, value in report.items():
        if isinstance(value, list) and len(value) > max_items:
            truncated[key] = value[:max_items]
            truncated[f"_{key}_note"] = (
                f"Showing {max_items} of {len(value)} items. "
                "Use get_full_report_section for complete data."
            )
        elif isinstance(value, dict) and len(str(value)) > 5000:
            truncated[key] = {k: v for i, (k, v) in enumerate(value.items()) if i < max_items}
            truncated[f"_{key}_note"] = "Truncated. Use get_full_report_section for complete data."
        else:
            truncated[key] = value
    return truncated


# ══════════════════════════════════════════════
# STATIC ANALYSIS TOOLS
# ══════════════════════════════════════════════


@mcp.tool()
async def upload_apk(file_path: str) -> str:
    """Upload an Android APK file to MobSF for analysis.

    This is the first step — upload the APK, then use scan_apk with the
    returned hash to trigger the actual analysis.

    Args:
        file_path: Absolute path to the APK file on disk.

    Returns:
        JSON with hash, file_name, and scan_type. The hash is needed for all subsequent operations.
    """
    client = get_client()
    result = await client.upload(file_path)
    return json.dumps(result, indent=2)


@mcp.tool()
async def scan_apk(hash: str) -> str:
    """Trigger static analysis on a previously uploaded APK.

    This performs decompilation, manifest analysis, code analysis,
    security scoring, and vulnerability detection.

    Args:
        hash: The MD5 hash returned from upload_apk.

    Returns:
        Scan results summary. Use get_report for detailed findings.
    """
    client = get_client()
    result = await client.scan(hash)
    # Return a summary rather than the full massive report
    summary = {
        "status": "scan_complete",
        "hash": hash,
        "hint": "Use get_report to retrieve detailed findings, "
        "or get_security_scorecard for a quick security overview.",
    }
    if "file_name" in result:
        summary["file_name"] = result["file_name"]
    if "app_name" in result:
        summary["app_name"] = result["app_name"]
    if "package_name" in result:
        summary["package_name"] = result["package_name"]
    if "version_name" in result:
        summary["version_name"] = result["version_name"]
    if "size" in result:
        summary["size"] = result["size"]
    return json.dumps(summary, indent=2)


@mcp.tool()
async def get_report(hash: str, sections: str = "") -> str:
    """Get the static analysis report for a scanned APK.

    Returns security findings including permissions, manifest analysis,
    code vulnerabilities, hardcoded secrets, network security, etc.

    Args:
        hash: The MD5 hash of the scanned APK.
        sections: Comma-separated list of specific sections to retrieve.
                  Available: permissions, manifest_analysis, code_analysis,
                  android_api, niap_analysis, urls, emails, strings,
                  firebase_urls, exported_activities, browsable_activities,
                  certificate_analysis, network_security, binary_analysis.
                  Leave empty to get all sections (truncated for large reports).

    Returns:
        JSON report with security findings.
    """
    client = get_client()
    report = await client.json_report(hash)

    if sections:
        requested = [s.strip() for s in sections.split(",")]
        filtered = {k: v for k, v in report.items() if k in requested}
        return json.dumps(filtered, indent=2, default=str)

    # Return truncated overview
    return json.dumps(_truncate_report(report), indent=2, default=str)


@mcp.tool()
async def get_security_scorecard(hash: str) -> str:
    """Get the security scorecard — a high-level security posture summary.

    Provides CVSS-style scoring across categories like: security, privacy,
    network, binary hardening, etc. Great for a quick risk assessment.

    Args:
        hash: The MD5 hash of the scanned APK.

    Returns:
        Security scorecard with category scores and grades.
    """
    client = get_client()
    result = await client.scorecard(hash)
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
async def list_scans() -> str:
    """List all recent scans in MobSF.

    Returns:
        List of previously scanned apps with their hashes, names, and timestamps.
    """
    client = get_client()
    result = await client.recent_scans()
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
async def search_scans(query: str) -> str:
    """Search through scanned apps by name, package, or hash.

    Args:
        query: Search term (app name, package name, or MD5 hash).

    Returns:
        Matching scan results.
    """
    client = get_client()
    result = await client.search(query)
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
async def view_source_file(hash: str, file_path: str) -> str:
    """View a specific source file from a decompiled APK.

    Useful for inspecting suspicious code flagged in the report —
    e.g., hardcoded keys, insecure crypto implementations, etc.

    Args:
        hash: The MD5 hash of the scanned APK.
        file_path: Relative path within the decompiled app (e.g., 'com/example/app/MainActivity.java').

    Returns:
        Source code content of the file.
    """
    client = get_client()
    result = await client.view_source(hash, file_path, "apk")
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
async def delete_scan(hash: str) -> str:
    """Delete a scan and its associated data from MobSF.

    Args:
        hash: The MD5 hash of the scan to delete.

    Returns:
        Confirmation of deletion.
    """
    client = get_client()
    result = await client.delete_scan(hash)
    return json.dumps(result, indent=2)


# ══════════════════════════════════════════════
# DYNAMIC ANALYSIS TOOLS
# ══════════════════════════════════════════════


@mcp.tool()
async def list_dynamic_apps() -> str:
    """List APKs available for dynamic analysis.

    These are apps that have been uploaded and can be installed
    on the connected emulator/device for runtime testing.

    Returns:
        List of apps ready for dynamic analysis.
    """
    client = get_client()
    result = await client.get_apps()
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
async def start_dynamic_analysis(hash: str) -> str:
    """Start dynamic analysis — installs and launches the app on the emulator.

    Requires a connected Android emulator or device configured with MobSF.
    The app will be installed, Frida server started, and runtime monitoring begins.

    Args:
        hash: The MD5 hash of the APK to analyze dynamically.

    Returns:
        Status of the dynamic analysis session.
    """
    client = get_client()
    result = await client.start_dynamic_analysis(hash)
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
async def stop_dynamic_analysis(hash: str) -> str:
    """Stop dynamic analysis and collect all runtime data.

    Gathers network traffic, API calls, logs, and generates the dynamic report.

    Args:
        hash: The MD5 hash of the APK being analyzed.

    Returns:
        Status and summary of collected data.
    """
    client = get_client()
    result = await client.stop_dynamic_analysis(hash)
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
async def get_dynamic_report(hash: str) -> str:
    """Get the dynamic analysis report after stopping analysis.

    Includes: API calls made, network traffic, leaked data, file access,
    crypto operations, TLS issues, and more.

    Args:
        hash: The MD5 hash of the analyzed APK.

    Returns:
        Dynamic analysis findings.
    """
    client = get_client()
    result = await client.dynamic_report(hash)
    return json.dumps(_truncate_report(result), indent=2, default=str)


@mcp.tool()
async def get_logcat(package: str) -> str:
    """Get Android logcat output filtered by package name.

    Useful for finding runtime errors, debug logs, leaked sensitive data.

    Args:
        package: The app's package name (e.g., 'com.example.app').

    Returns:
        Logcat output for the specified package.
    """
    client = get_client()
    result = await client.get_logcat(package)
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
async def run_adb_command(command: str) -> str:
    """Execute an ADB command on the connected emulator/device.

    Useful for: listing packages, checking running processes, examining
    app data directories, dumping preferences, etc.

    Args:
        command: ADB shell command to execute (e.g., 'pm list packages', 'ls /data/data/com.app').

    Returns:
        Command output.
    """
    client = get_client()
    result = await client.adb_command(command)
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
async def test_exported_activities(hash: str) -> str:
    """Test all exported activities in the APK for unauthorized access.

    Attempts to launch each exported activity without proper authentication
    to find activities that can be accessed without going through normal app flow.

    Args:
        hash: The MD5 hash of the APK.

    Returns:
        Results of activity testing — which activities are accessible.
    """
    client = get_client()
    result = await client.activity_tester(hash, "exported")
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
async def launch_activity(hash: str, activity: str) -> str:
    """Launch a specific activity on the device.

    Args:
        hash: The MD5 hash of the APK.
        activity: Fully qualified activity name (e.g., 'com.example.app/.SecretActivity').

    Returns:
        Result of launching the activity.
    """
    client = get_client()
    result = await client.start_activity(hash, activity)
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
async def run_tls_tests(hash: str) -> str:
    """Run TLS/SSL security tests on the app's network connections.

    Tests for: certificate pinning bypass, weak cipher suites,
    cleartext traffic, TLS version issues.

    Args:
        hash: The MD5 hash of the APK.

    Returns:
        TLS security test results.
    """
    client = get_client()
    result = await client.tls_tests(hash)
    return json.dumps(result, indent=2, default=str)


# ══════════════════════════════════════════════
# FRIDA INSTRUMENTATION TOOLS
# ══════════════════════════════════════════════


@mcp.tool()
async def frida_instrument(
    hash: str,
    default_hooks: str = "",
    auxiliary_hooks: str = "",
    custom_script: str = "",
) -> str:
    """Run Frida instrumentation on the app during dynamic analysis.

    Frida hooks into the running app to intercept function calls,
    bypass security controls, and monitor runtime behavior.

    Args:
        hash: The MD5 hash of the APK (dynamic analysis must be running).
        default_hooks: Comma-separated built-in hooks to enable.
                       Options: api_monitor, ssl_pinning_bypass, root_bypass,
                       debugger_check_bypass, ssl_pinning_bypass2
        auxiliary_hooks: Comma-separated auxiliary hook names from MobSF's scripts.
        custom_script: Custom Frida JavaScript code to inject.
                       Example: 'Java.perform(function(){ ... })'

    Returns:
        Instrumentation results.
    """
    client = get_client()
    result = await client.frida_instrument(
        hash=hash,
        default_hooks=default_hooks,
        auxiliary_hooks=auxiliary_hooks,
        frida_code=custom_script,
    )
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
async def frida_monitor_apis(hash: str) -> str:
    """Get Frida API monitoring results.

    Shows which sensitive APIs the app called at runtime: crypto, file I/O,
    network, IPC, database, reflection, etc.

    Args:
        hash: The MD5 hash of the APK.

    Returns:
        API monitoring data showing runtime behavior.
    """
    client = get_client()
    result = await client.frida_api_monitor(hash)
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
async def frida_get_logs(hash: str) -> str:
    """Get Frida hook output logs.

    Contains the output from running instrumentation scripts —
    intercepted values, bypassed checks, decrypted data, etc.

    Args:
        hash: The MD5 hash of the APK.

    Returns:
        Frida script output logs.
    """
    client = get_client()
    result = await client.frida_logs(hash)
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
async def frida_list_scripts() -> str:
    """List available built-in Frida scripts in MobSF.

    These are pre-written hooks for common Android security testing tasks.

    Returns:
        List of available Frida scripts and their descriptions.
    """
    client = get_client()
    result = await client.frida_list_scripts("android")
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
async def frida_get_dependencies(hash: str) -> str:
    """Get/install Frida dependencies for the app being analyzed.

    Ensures the Frida server and required dependencies are available
    on the connected device. Call this before running Frida hooks
    if you encounter dependency errors.

    Args:
        hash: The MD5 hash of the APK.

    Returns:
        Status of Frida dependency installation.
    """
    client = get_client()
    result = await client.frida_get_dependencies(hash)
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
async def frida_get_script_code(scripts: str) -> str:
    """Get the source code of Frida scripts.

    Useful for understanding what a hook does before running it,
    or as a base for writing custom instrumentation.

    Args:
        scripts: Comma-separated list of script filenames to retrieve.

    Returns:
        Script source code.
    """
    client = get_client()
    script_list = [s.strip() for s in scripts.split(",")]
    result = await client.frida_get_script(script_list, "android")
    return json.dumps(result, indent=2, default=str)


# ══════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════


def main():
    """Run the MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
