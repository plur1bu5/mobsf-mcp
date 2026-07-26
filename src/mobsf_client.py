"""MobSF REST API client."""

from __future__ import annotations

import httpx
from pathlib import Path


class MobSFClient:
    """Async client for MobSF REST API v1."""

    def __init__(self, base_url: str = "http://localhost:8000", api_key: str = ""):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            headers={"X-Mobsf-Api-Key": self.api_key},
            timeout=300.0,  # scans can take a while
        )

    async def close(self):
        await self._client.aclose()

    # ──────────────────────────────────────────────
    # Static Analysis
    # ──────────────────────────────────────────────

    async def upload(self, file_path: str) -> dict:
        """Upload an APK/IPA/ZIP for analysis."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        with open(path, "rb") as f:
            resp = await self._client.post(
                "/api/v1/upload",
                files={"file": (path.name, f, "application/octet-stream")},
            )
        resp.raise_for_status()
        return resp.json()

    async def scan(self, hash: str) -> dict:
        """Trigger static analysis scan for an uploaded file."""
        resp = await self._client.post(
            "/api/v1/scan",
            data={"hash": hash},
        )
        resp.raise_for_status()
        return resp.json()

    async def json_report(self, hash: str) -> dict:
        """Get the full JSON report for a completed scan."""
        resp = await self._client.post(
            "/api/v1/report_json",
            data={"hash": hash},
        )
        resp.raise_for_status()
        return resp.json()

    async def scorecard(self, hash: str) -> dict:
        """Get the security scorecard for a scan."""
        resp = await self._client.post(
            "/api/v1/scorecard",
            data={"hash": hash},
        )
        resp.raise_for_status()
        return resp.json()

    async def scan_logs(self, hash: str) -> dict:
        """Get scan logs."""
        resp = await self._client.post(
            "/api/v1/scan_logs",
            data={"hash": hash},
        )
        resp.raise_for_status()
        return resp.json()

    async def recent_scans(self) -> dict:
        """List recent scans."""
        resp = await self._client.get("/api/v1/scans")
        resp.raise_for_status()
        return resp.json()

    async def delete_scan(self, hash: str) -> dict:
        """Delete a scan by hash."""
        resp = await self._client.post(
            "/api/v1/delete_scan",
            data={"hash": hash},
        )
        resp.raise_for_status()
        return resp.json()

    async def search(self, query: str) -> dict:
        """Search scans by checksum or text."""
        resp = await self._client.post(
            "/api/v1/search",
            data={"query": query},
        )
        resp.raise_for_status()
        return resp.json()

    async def view_source(self, hash: str, file: str, type: str) -> dict:
        """View a source file from a scanned app.

        Args:
            hash: Scan hash (MD5)
            file: Relative path to the file within the decompiled app
            type: File type - 'apk' for Android, 'ipa' for iOS
        """
        resp = await self._client.post(
            "/api/v1/view_source",
            data={"hash": hash, "file": file, "type": type},
        )
        resp.raise_for_status()
        return resp.json()

    # ──────────────────────────────────────────────
    # Dynamic Analysis
    # ──────────────────────────────────────────────

    async def get_apps(self) -> dict:
        """Get list of apps available for dynamic analysis."""
        resp = await self._client.get("/api/v1/dynamic/get_apps")
        resp.raise_for_status()
        return resp.json()

    async def start_dynamic_analysis(self, hash: str) -> dict:
        """Start dynamic analysis for an app."""
        resp = await self._client.post(
            "/api/v1/dynamic/start_analysis",
            data={"hash": hash},
        )
        resp.raise_for_status()
        return resp.json()

    async def stop_dynamic_analysis(self, hash: str) -> dict:
        """Stop dynamic analysis and collect results."""
        resp = await self._client.post(
            "/api/v1/dynamic/stop_analysis",
            data={"hash": hash},
        )
        resp.raise_for_status()
        return resp.json()

    async def dynamic_report(self, hash: str) -> dict:
        """Get dynamic analysis JSON report."""
        resp = await self._client.post(
            "/api/v1/dynamic/report_json",
            data={"hash": hash},
        )
        resp.raise_for_status()
        return resp.json()

    async def get_logcat(self, package: str) -> dict:
        """Get logcat output for a package during dynamic analysis."""
        resp = await self._client.post(
            "/api/v1/android/logcat",
            data={"package": package},
        )
        resp.raise_for_status()
        return resp.json()

    async def adb_command(self, cmd: str) -> dict:
        """Execute an ADB command on the connected device/emulator."""
        resp = await self._client.post(
            "/api/v1/android/adb_command",
            data={"cmd": cmd},
        )
        resp.raise_for_status()
        return resp.json()

    async def activity_tester(self, hash: str, test: str = "exported") -> dict:
        """Test exported activities.

        Args:
            hash: Scan hash
            test: Test type - 'exported' to test exported activities
        """
        resp = await self._client.post(
            "/api/v1/android/activity",
            data={"hash": hash, "test": test},
        )
        resp.raise_for_status()
        return resp.json()

    async def start_activity(self, hash: str, activity: str) -> dict:
        """Start a specific activity on the device."""
        resp = await self._client.post(
            "/api/v1/android/start_activity",
            data={"hash": hash, "activity": activity},
        )
        resp.raise_for_status()
        return resp.json()

    async def tls_tests(self, hash: str) -> dict:
        """Run TLS/SSL security tests."""
        resp = await self._client.post(
            "/api/v1/android/tls_tests",
            data={"hash": hash},
        )
        resp.raise_for_status()
        return resp.json()

    # ──────────────────────────────────────────────
    # Frida
    # ──────────────────────────────────────────────

    async def frida_instrument(
        self,
        hash: str,
        default_hooks: str = "",
        auxiliary_hooks: str = "",
        frida_code: str = "",
    ) -> dict:
        """Run Frida instrumentation on the app.

        Args:
            hash: Scan hash
            default_hooks: Comma-separated default hooks (e.g. 'api_monitor,ssl_pinning_bypass')
            auxiliary_hooks: Comma-separated auxiliary hook names
            frida_code: Custom Frida script code
        """
        resp = await self._client.post(
            "/api/v1/frida/instrument",
            data={
                "hash": hash,
                "default_hooks": default_hooks,
                "auxiliary_hooks": auxiliary_hooks,
                "frida_code": frida_code,
            },
        )
        resp.raise_for_status()
        return resp.json()

    async def frida_api_monitor(self, hash: str) -> dict:
        """Get Frida API monitor results."""
        resp = await self._client.post(
            "/api/v1/frida/api_monitor",
            data={"hash": hash},
        )
        resp.raise_for_status()
        return resp.json()

    async def frida_logs(self, hash: str) -> dict:
        """Get Frida instrumentation logs."""
        resp = await self._client.post(
            "/api/v1/frida/logs",
            data={"hash": hash},
        )
        resp.raise_for_status()
        return resp.json()

    async def frida_list_scripts(self, device: str = "android") -> dict:
        """List available Frida scripts.

        Args:
            device: Device type - 'android' or 'ios'
        """
        resp = await self._client.post(
            "/api/v1/frida/list_scripts",
            data={"device": device},
        )
        resp.raise_for_status()
        return resp.json()

    async def frida_get_script(self, scripts: list[str], device: str = "android") -> dict:
        """Get content of Frida scripts.

        Args:
            scripts: List of script filenames
            device: Device type - 'android' or 'ios'
        """
        resp = await self._client.post(
            "/api/v1/frida/get_script",
            data={"scripts[]": scripts, "device": device},
        )
        resp.raise_for_status()
        return resp.json()

    async def frida_get_dependencies(self, hash: str) -> dict:
        """Get/install Frida dependencies."""
        resp = await self._client.post(
            "/api/v1/frida/get_dependencies",
            data={"hash": hash},
        )
        resp.raise_for_status()
        return resp.json()
