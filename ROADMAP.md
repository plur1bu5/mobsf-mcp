# Roadmap

Short, medium, and long-term plans for mobsf-mcp. PRs welcome.

## Short-term

- **Frida/API 33 fix** — MobSF v4.5.1 ships Frida 17.15.3 which crashes on Android 13+. Either wait for upstream update or ship a custom `Dockerfile` pinning Frida 16.x to unblock full DAST on API 33.
- **iOS support** — the MobSF client already handles IPA endpoints. Add `upload_ipa`, `scan_ipa`, and iOS-specific tools. Doubles the audience with ~4 new tool wrappers.
- **More MobSF API coverage** — several endpoints are available but not exposed as MCP tools:
  - `generate_pdf_report` — generate a PDF security report
  - `compare_apps` — diff two scan results side by side
  - `suppress_by_rule` / `list_suppressions` / `delete_suppression` — false positive management for repeat scans
  - `get_scan_logs` — detailed scan progress (client code exists, just needs a `@mcp.tool()` decorator)

## Medium-term

- **Dockerized MCP server** — a `Dockerfile` that bundles `mobsf-mcp` so users don't need Python. One `docker run` and the tools are ready.
- **Better error messages** — dynamic tools currently return raw MobSF errors. Wrap them with actionable agent-friendly messages ("No emulator connected. Start one with: `emulator -avd mobsf ...`").
- **CI pipeline** — GitHub Actions that spins up MobSF + emulator, runs `test_pipeline.py`, and blocks PRs that break tools.
- **Volume-backed API key in docker-compose** — currently the entrypoint wrapper lives in `mobsf-data/`. Move it into the repo as a Docker-managed init so `docker compose up` requires zero manual file creation.

## Long-term

- **Pre-built emulator integration** — the README now documents `budtmo/docker-android` as an option. Next step: ship a unified `docker-compose.yml` that starts both MobSF and the emulator in one command, with ADB auto-wired.
- **Agent workflow guides** — documented patterns for Hermes, Claude Code, and autonomous workflows: "scan this APK, if score < 50 run dynamic analysis, if secrets found inspect source, generate PDF report."
- **Demo video/GIF** — screen capture of an LLM autonomously analyzing an APK from upload to report.
- **Broader MCP ecosystem** — contribute the patterns learned here (tool design, error handling, ADB/Docker wiring) back to the MCP community as a reference implementation.
