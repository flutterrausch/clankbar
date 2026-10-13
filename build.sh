#!/bin/bash
# Builds Clankbar.app and installs it to /Applications.
set -euo pipefail
cd "$(dirname "$0")"

APP=build/Clankbar.app
if [ -d build ]; then trash build; fi
mkdir -p "$APP/Contents/MacOS"

swiftc -O -parse-as-library -swift-version 5 -target arm64-apple-macos14.0 \
  -o "$APP/Contents/MacOS/Clankbar" Sources/Clankbar.swift

cat > "$APP/Contents/Info.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key><string>local.clankbar</string>
  <key>CFBundleName</key><string>Clankbar</string>
  <key>CFBundleDisplayName</key><string>Clankbar</string>
  <key>CFBundleExecutable</key><string>Clankbar</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>LSMinimumSystemVersion</key><string>14.0</string>
  <key>LSUIElement</key><true/>
</dict>
</plist>
EOF

codesign --force --sign - "$APP"

pkill -x Clankbar 2>/dev/null || true
if [ -d /Applications/Clankbar.app ]; then trash /Applications/Clankbar.app; fi
cp -R "$APP" /Applications/
open /Applications/Clankbar.app
echo "Installed /Applications/Clankbar.app"
