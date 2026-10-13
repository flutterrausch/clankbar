#!/bin/bash
# Builds ClaudeBar.app and installs it to /Applications.
set -euo pipefail
cd "$(dirname "$0")"

APP=build/ClaudeBar.app
if [ -d build ]; then trash build; fi
mkdir -p "$APP/Contents/MacOS"

swiftc -O -parse-as-library -swift-version 5 -target arm64-apple-macos14.0 \
  -o "$APP/Contents/MacOS/ClaudeBar" Sources/ClaudeBar.swift

cat > "$APP/Contents/Info.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key><string>local.ingo.claudebar</string>
  <key>CFBundleName</key><string>ClaudeBar</string>
  <key>CFBundleDisplayName</key><string>ClaudeBar</string>
  <key>CFBundleExecutable</key><string>ClaudeBar</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>LSMinimumSystemVersion</key><string>14.0</string>
  <key>LSUIElement</key><true/>
</dict>
</plist>
EOF

codesign --force --sign - "$APP"

pkill -x ClaudeBar 2>/dev/null || true
if [ -d /Applications/ClaudeBar.app ]; then trash /Applications/ClaudeBar.app; fi
cp -R "$APP" /Applications/
open /Applications/ClaudeBar.app
echo "Installed /Applications/ClaudeBar.app"
