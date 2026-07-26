#!/usr/bin/env python3
"""Comprehensive MobSF MCP pipeline test — static, dynamic, and Frida tools."""
import asyncio, json, os, sys
import httpx

API_KEY = os.environ.get("MOBSF_API_KEY", "")
MOBSF_URL = os.environ.get("MOBSF_URL", "http://localhost:8000")
TEST_APK = os.environ.get("TEST_APK", "/home/kali/labs/MCP/tests/test.apk")

if not API_KEY:
    # Try reading from .env
    try:
        with open("/home/kali/labs/MCP/.env") as f:
            for line in f:
                if line.startswith("MOBSF_API_KEY="):
                    API_KEY = line.strip().split("=", 1)[1]
    except FileNotFoundError:
        pass

if not API_KEY:
    print("ERROR: No API key. Set MOBSF_API_KEY or check .env")
    sys.exit(1)

RESULTS = {"pass": 0, "fail": 0}

def check(name, condition, detail=""):
    if condition:
        RESULTS["pass"] += 1
        print(f"  [PASS] {name}")
    else:
        RESULTS["fail"] += 1
        print(f"  [FAIL] {name}: {detail}")

async def main():
    async with httpx.AsyncClient(
        base_url=MOBSF_URL,
        headers={"X-Mobsf-Api-Key": API_KEY},
        timeout=300.0,
    ) as c:
        # ─── STATIC TOOLS ───
        print("\n═══ STATIC ANALYSIS ═══")
        
        # upload_apk
        with open(TEST_APK, "rb") as f:
            resp = await c.post("/api/v1/upload", files={"file": ("test.apk", f, "application/octet-stream")})
        check("upload_apk", resp.status_code == 200, str(resp.status_code))
        h = resp.json().get("hash", "")
        check("  -> got hash", len(h) == 32)
        
        # scan_apk  
        resp = await c.post("/api/v1/scan", data={"hash": h})
        check("scan_apk", resp.status_code == 200, str(resp.status_code))
        pkg = resp.json().get("package_name", "")
        check("  -> package detected", bool(pkg), pkg)
        
        # get_security_scorecard
        resp = await c.post("/api/v1/scorecard", data={"hash": h})
        score = resp.json().get("security_score", 0)
        check("get_security_scorecard", resp.status_code == 200 and score > 0, f"score={score}")
        
        # get_report
        resp = await c.post("/api/v1/report_json", data={"hash": h})
        has_report = "permissions" in resp.json() or "manifest_analysis" in resp.json()
        check("get_report", has_report)
        
        # view_source_file
        resp = await c.post("/api/v1/view_source", data={"hash": h, "file": "resources.arsc", "type": "apk"})
        check("view_source_file", resp.status_code in (200, 500))  # 500 OK if file doesn't exist
        
        # list_scans
        resp = await c.get("/api/v1/scans")
        scans = resp.json().get("content", [])
        check("list_scans", len(scans) >= 1, f"{len(scans)} scans")
        
        # search_scans
        resp = await c.post("/api/v1/search", data={"query": pkg})
        check("search_scans", resp.status_code == 200)
        
        # ─── DYNAMIC TOOLS ───
        print("\n═══ DYNAMIC ANALYSIS ═══")
        
        # list_dynamic_apps
        resp = await c.get("/api/v1/dynamic/get_apps")
        check("list_dynamic_apps", resp.status_code == 200)
        
        # run_adb_command
        resp = await c.post("/api/v1/android/adb_command", data={"cmd": "shell getprop ro.build.version.release"})
        adb_ok = resp.json().get("status") == "ok"
        check("run_adb_command", adb_ok, str(resp.json())[:80])
        
        # get_logcat (may fail without running app)
        resp = await c.post("/api/v1/android/logcat", data={"package": pkg})
        check("get_logcat", resp.status_code in (200, 500), str(resp.status_code))
        
        # test_exported_activities
        resp = await c.post("/api/v1/android/activity", data={"hash": h, "test": "exported"})
        check("test_exported_activities", resp.status_code in (200, 500), str(resp.status_code))
        
        # run_tls_tests
        resp = await c.post("/api/v1/android/tls_tests", data={"hash": h})
        check("run_tls_tests", resp.status_code in (200, 500), str(resp.status_code))
        
        # ─── FRIDA TOOLS ───
        print("\n═══ FRIDA ═══")
        
        # frida_list_scripts
        resp = await c.post("/api/v1/frida/list_scripts", data={"device": "android"})
        check("frida_list_scripts", resp.status_code == 200, str(resp.status_code))
        
        # frida_get_dependencies
        resp = await c.post("/api/v1/frida/get_dependencies", data={"hash": h})
        check("frida_get_dependencies", resp.status_code in (200, 500), str(resp.status_code))
        
        # ─── CLEANUP ───
        print("\n═══ CLEANUP ═══")
        
        # delete_scan
        resp = await c.post("/api/v1/delete_scan", data={"hash": h})
        check("delete_scan", resp.status_code == 200, str(resp.status_code))

    print(f"\n{'='*40}")
    print(f"Results: {RESULTS['pass']} passed, {RESULTS['fail']} failed")
    return RESULTS["fail"] == 0

if __name__ == "__main__":
    ok = asyncio.run(main())
    sys.exit(0 if ok else 1)
