#!/usr/bin/env bash
# mobsf-mcp: One-command setup for agentic Android security analysis
# Usage: bash scripts/setup.sh
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
err()   { echo -e "${RED}[x]${NC} $*"; }

# ─── Config ──────────────────────────────────────
ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-$HOME/android-sdk}"
AVD_NAME="${AVD_NAME:-mobsf}"
API_LEVEL="33"
SYSTEM_IMAGE="system-images;android-${API_LEVEL};google_apis;x86_64"
DEVICE="pixel_6"
MOBSF_URL="${MOBSF_URL:-http://localhost:8000}"
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

info "mobsf-mcp setup starting..."
echo "  Android SDK: $ANDROID_SDK_ROOT"
echo "  AVD:         $AVD_NAME"
echo "  API Level:   $API_LEVEL"
echo "  System Img:  $SYSTEM_IMAGE"
echo "  MobSF URL:   $MOBSF_URL"
echo ""

# ─── 1. Environment ──────────────────────────────
info "Step 1: Environment variables"

if ! grep -q "ANDROID_SDK_ROOT" ~/.zshrc 2>/dev/null; then
    cat >> ~/.zshrc <<'EOF'

# Android SDK (added by mobsf-mcp setup)
export ANDROID_SDK_ROOT="$HOME/android-sdk"
export ANDROID_AVD_HOME="$HOME/.config/.android/avd"
export PATH="$ANDROID_SDK_ROOT/cmdline-tools/latest/bin:$ANDROID_SDK_ROOT/platform-tools:$ANDROID_SDK_ROOT/emulator:$PATH"
EOF
    info "Added Android SDK vars to ~/.zshrc"
else
    info "Android SDK vars already in ~/.zshrc"
fi

export ANDROID_AVD_HOME="$HOME/.config/.android/avd"
export PATH="$ANDROID_SDK_ROOT/cmdline-tools/latest/bin:$ANDROID_SDK_ROOT/platform-tools:$ANDROID_SDK_ROOT/emulator:$PATH"

# ─── 2. SDK Manager ──────────────────────────────
info "Step 2: Checking SDK manager..."

if [ ! -f "$ANDROID_SDK_ROOT/cmdline-tools/latest/bin/sdkmanager" ]; then
    err "sdkmanager not found at $ANDROID_SDK_ROOT/cmdline-tools/latest/bin/sdkmanager"
    err "Install Android SDK command-line tools from: https://developer.android.com/studio#command-line-tools-only"
    exit 1
fi

yes | sdkmanager --licenses > /dev/null 2>&1

# ─── 3. System Image ─────────────────────────────
info "Step 3: Installing system image (google_apis for root/DAST support)..."

if [ -d "$ANDROID_SDK_ROOT/system-images/android-${API_LEVEL}/google_apis/x86_64" ] && \
   [ -f "$ANDROID_SDK_ROOT/system-images/android-${API_LEVEL}/google_apis/x86_64/system.img" ]; then
    info "System image already installed."
else
    info "Downloading $SYSTEM_IMAGE..."
    sdkmanager "$SYSTEM_IMAGE" "platforms;android-${API_LEVEL}" "platform-tools"
    info "System image installed."
fi

# ─── 4. AVD ──────────────────────────────────────
info "Step 4: Creating AVD..."

if avdmanager list avd 2>/dev/null | grep -q "$AVD_NAME"; then
    CURRENT_API=$(grep "target=" "$HOME/.config/.android/avd/${AVD_NAME}.ini" 2>/dev/null | grep -oP 'android-\K\d+' || echo "0")
    if [ "$CURRENT_API" != "$API_LEVEL" ]; then
        warn "Deleting old AVD (API $CURRENT_API)..."
        yes | avdmanager delete avd -n "$AVD_NAME" > /dev/null 2>&1
    else
        CURRENT_TAG=$(grep "tag.id=" "$HOME/.config/.android/avd/${AVD_NAME}.avd/config.ini" 2>/dev/null | cut -d= -f2 || echo "")
        if [ "$CURRENT_TAG" != "google_apis" ]; then
            warn "AVD has wrong tag ($CURRENT_TAG), recreating..."
            yes | avdmanager delete avd -n "$AVD_NAME" > /dev/null 2>&1
        else
            info "AVD already exists with correct config. Skipping creation."
        fi
    fi
fi

if ! avdmanager list avd 2>/dev/null | grep -q "$AVD_NAME"; then
    echo "no" | avdmanager create avd \
        -n "$AVD_NAME" \
        -k "$SYSTEM_IMAGE" \
        -d "$DEVICE" \
        -f
    info "AVD '$AVD_NAME' created (device: $DEVICE, API: $API_LEVEL, google_apis)"
fi

# ─── 5. ADB Keys ─────────────────────────────────
info "Step 5: Setting up ADB keys for Docker..."

mkdir -p "$SCRIPT_DIR/mobsf-data/.android"
if [ -f "$HOME/.android/adbkey" ]; then
    cp "$HOME/.android/adbkey" "$HOME/.android/adbkey.pub" "$SCRIPT_DIR/mobsf-data/.android/" 2>/dev/null || true
    chmod 644 "$SCRIPT_DIR/mobsf-data/.android/adbkey" 2>/dev/null || true
    info "ADB keys copied for Docker container"
else
    warn "No ADB keys found — run 'adb devices' once to generate them"
fi

# ─── 6. MobSF API Cap Patch ──────────────────────
info "Step 6: Creating API cap patch for MobSF..."

cat > "$SCRIPT_DIR/mobsf-data/entrypoint-wrapper.sh" << 'ENTRYPOINT'
#!/bin/bash
# Patches MobSF to support API 33+ for dynamic analysis
sed -i 's/ANDROID_API_SUPPORTED = 30/ANDROID_API_SUPPORTED = 34/' \
    /home/mobsf/Mobile-Security-Framework-MobSF/mobsf/DynamicAnalyzer/views/android/environment.py 2>/dev/null
exec /home/mobsf/Mobile-Security-Framework-MobSF/scripts/entrypoint.sh "$@"
ENTRYPOINT
chmod +x "$SCRIPT_DIR/mobsf-data/entrypoint-wrapper.sh"
info "Entrypoint wrapper created"

# ─── 7. MobSF Docker ─────────────────────────────
info "Step 7: Starting MobSF Docker..."

cd "$SCRIPT_DIR"
docker compose up -d 2>&1 | tail -3

info "Waiting for MobSF to become healthy..."
for i in $(seq 1 30); do
    if curl -sf "$MOBSF_URL" > /dev/null 2>&1; then
        info "MobSF is up at $MOBSF_URL"
        break
    fi
    sleep 2
done

# ─── 8. API Key ──────────────────────────────────
info "Step 8: Retrieving API key..."

API_KEY=$(docker logs mobsf 2>&1 | grep "REST API Key" | tail -1 | grep -oP '[a-f0-9]{64}' || echo "")

if [ -n "$API_KEY" ]; then
    info "API Key: $API_KEY"
    cat > .env <<EOF
# MobSF Configuration
MOBSF_URL=$MOBSF_URL
MOBSF_API_KEY=$API_KEY
EOF
    info "Created .env with API key"
    export MOBSF_API_KEY="$API_KEY"
else
    warn "Could not auto-detect API key. Check: docker logs mobsf 2>&1 | grep 'REST API Key'"
fi

# ─── 9. Install MCP server ───────────────────────
info "Step 9: Installing mobsf-mcp..."

pip install -e . > /dev/null 2>&1
info "mobsf-mcp installed."

# ─── 10. Emulator ────────────────────────────────
info "Step 10: Emulator"

if [ "${SKIP_EMULATOR:-0}" = "1" ]; then
    warn "Skipping emulator start (SKIP_EMULATOR=1)"
else
    info "To start the emulator (headless, with writable system):"
    echo ""
    echo "  adb kill-server  # avoid ADB conflicts with Docker"
    echo "  emulator -avd $AVD_NAME -no-window -no-audio -no-snapshot \\"
    echo "    -writable-system -gpu swiftshader_indirect -memory 2048 &"
    echo ""
    echo "  adb wait-for-device"
    echo "  adb root && adb remount  # required for DAST"
    echo "  adb shell 'while [[ -z \$(getprop sys.boot_completed) ]]; do sleep 5; done'"
    echo ""
fi

# ─── Done ────────────────────────────────────────
echo ""
info "Setup complete!"
echo "  MCP server:  mobsf-mcp"
echo "  MobSF:       $MOBSF_URL"
echo "  API key:     ${MOBSF_API_KEY:-see .env}"
echo "  Config:      MCP client -> mobsf-mcp command"
echo ""
echo "  Source:      source ~/.zshrc  # to load Android SDK vars"
echo "  Docker:      docker compose up -d"
echo "  Emulator:    see instructions above"
echo "  Test:        python3 scripts/test_pipeline.py"
