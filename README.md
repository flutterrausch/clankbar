# ClankBar

A tiny macOS menu bar app that shows your Claude 5-hour and weekly limits for **the account the Claude desktop app is signed into**.

## Why it exists

Usage trackers like CodexBar and OpenUsage get their Claude login from your browser or from Claude Code. If the Claude desktop app is signed into a different account, they show the wrong numbers, and switching accounts in the app doesn't change what they display.

ClankBar reads only the desktop app's own claude.ai session, fresh on every refresh, so it always shows the account you're actually using in the app.

## What it shows

- **Menu bar:** two stacked bars showing what's left, session on top and week below (like CodexBar).
- **Dropdown:** a bar for each limit with a pace marker, % left, reset time, whether you're ahead or behind an even pace, and either "At this rate: ~X% by reset" or a "Runs out in …" warning.

## Build

```bash
bash build.sh
```

Needs Xcode's Swift toolchain on macOS 14 or later. This builds `ClankBar.app` and installs it to `/Applications`. The app has no dependencies, updater or analytics.

## How it works and caveats

- The app reads the Claude desktop app's cookie database and decrypts it with the `Claude Safe Storage` Keychain item. It then calls claude.ai's usage endpoint, the same one behind the usage page in Claude's settings. It does this every 2 minutes, and again when you open the dropdown if the numbers are more than a minute old.
- The session cookie stays in memory and is only ever sent to claude.ai.
- The usage endpoint is undocumented and may change or break at any time.
- Claude's consumer terms restrict automated access. A read-only usage check is low-risk, but use it at your own discretion.
- Not affiliated with Anthropic.
