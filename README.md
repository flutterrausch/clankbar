# ClankBar

A tiny macOS menu bar app that shows your Claude 5-hour and weekly limits for **the account the Claude desktop app is signed into**.

## Why it exists

**Multiple accounts.** If you switch between Claude accounts in the desktop app, for example a personal and a work account, you want to see the limits of whichever account you're on at the moment.

Usage trackers like CodexBar and OpenUsage get their Claude login from your browser or from Claude Code, not from the desktop app. So after a switch they keep showing the old account.

ClankBar reads only the desktop app's own claude.ai session, fresh on every refresh, so it follows your account switches.

## What it shows

- **Menu bar:** two stacked bars showing what's left, session on top and week below (like CodexBar).
- **Dropdown:** a bar for each limit with a pace marker, % left, reset time, whether you're ahead or behind an even pace, and a "Runs out in …" warning when you're on track to hit the limit early.
- **Other accounts:** every account ClankBar has seen is shown below in the same layout, dimmed, with its last-seen numbers marked "as of …". Windows whose reset time has passed since then show as reset. It only stores those numbers, never logins.

## Switching accounts

The Claude desktop app has no account switcher, so you log out and back in:

1. In the Claude desktop app, click your name at the bottom left and choose **Log out**.
2. Sign in with the other account.

ClankBar picks up the new account on its next refresh, within 2 minutes. To see it right away, click **Refresh** in the dropdown. The previous account moves to the dimmed list below.

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

## License

MIT, see [LICENSE](LICENSE).
