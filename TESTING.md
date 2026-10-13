# Testing: account switching

Switching works in both directions (tested 2026-10-13): each account shows its own email, limits and icon bars. Still open are the brief moment right after a switch, a fresh 5-hour window, and the "Runs out" warning.

## Checklist

1. ⏳ Open the ClankBar dropdown, then switch accounts in the Claude desktop app.
   - Expected: at most a grey "Waiting for Claude desktop to finish switching accounts…" for up to a minute, never the red "rejected the session" error.
   - Afterwards the new account's email shows at the top. ✅ (email correct; not yet watched whether any message flashes in between)
2. ⏳ The second account hasn't used its 5-hour window yet.
   - Expected: Session shows "100% left" and "Not started yet" (no blank line). Missed: the window had already started. Retry when an account has been idle for 5+ hours.
3. ✅ Send one message on the second account, then click Refresh.
   - Expected: Session gets a reset time; the pace line appears after ~5 minutes.
4. ✅ Switch back to the first account.
   - Expected: same as step 1, and the menu bar icon updates to that account's bars.
5. ⏳ While behind pace, the orange "Runs out in …" line appears only together with "… in deficit".

## If something's off

- Note the exact message in the dropdown and roughly how long after the switch it appeared.
- The cookie DB is `~/Library/Application Support/Claude/Cookies`. `lastActiveOrg` and `sessionKey` are the two cookies that matter.
- Relaunching with the dropdown open helps for screenshots: `open /Applications/ClankBar.app --args --open`.
