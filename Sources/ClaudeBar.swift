// ClaudeBar: menu bar app showing the 5-hour and weekly limits of whatever
// account the Claude desktop app is signed into. Reads the app's claude.ai cookies
// (decrypted with the "Claude Safe Storage" Keychain item) on every refresh, so it
// follows account switches. Visuals follow CodexBar: two stacked "remaining" bars.

import AppKit
import CommonCrypto
import ServiceManagement
import SQLite3
import SwiftUI

// MARK: - Model

struct Limit: Identifiable {
    let id: String
    let label: String
    let used: Double
    let resetsAt: Date?
    let window: TimeInterval

    var left: Double { max(0, 100 - used) }

    /// Usage you'd be at if spending evenly over the window.
    var expected: Double? {
        guard let resetsAt else { return nil }
        let elapsed = window - resetsAt.timeIntervalSinceNow
        return min(100, max(0, elapsed / window * 100))
    }

    var paceText: String? {
        guard let expected else { return nil }
        let d = used - expected
        if abs(d) < 2 { return "On pace" }
        return String(format: "%.0f%% %@", abs(d), d > 0 ? "in deficit" : "in reserve")
    }

    var inDeficit: Bool { (expected.map { used - $0 >= 2 }) ?? false }

    var projection: String? {
        guard let resetsAt else { return nil }
        let elapsed = window - resetsAt.timeIntervalSinceNow
        guard used > 0, elapsed > 300 else { return "Lasts until reset" }
        let runout = elapsed * (100 - used) / used  // time left at the average rate so far
        return runout >= resetsAt.timeIntervalSinceNow ? "Lasts until reset" : "Runs out in \(duration(runout))"
    }
}

struct Snapshot {
    let email: String
    let limits: [Limit]
    let updated: Date
}

func duration(_ t: TimeInterval) -> String {
    let m = max(0, Int(t / 60))
    if m >= 1440 { return "\(m / 1440)d \(m % 1440 / 60)h" }
    if m >= 60 { return "\(m / 60)h \(m % 60)m" }
    return "\(m)m"
}

// MARK: - Claude desktop session

enum FetchError: LocalizedError {
    case keychain, notSignedIn, http(Int), badResponse

    var errorDescription: String? {
        switch self {
        case .keychain: "Can't read \"Claude Safe Storage\" from the Keychain."
        case .notSignedIn: "Claude desktop app isn't signed in."
        case .http(let code): code == 401 || code == 403
            ? "claude.ai rejected the session (HTTP \(code)). Open Claude desktop once, then refresh."
            : "claude.ai returned HTTP \(code)."
        case .badResponse: "Unexpected response from claude.ai."
        }
    }
}

enum ClaudeDesktop {
    static let cookiesPath = NSHomeDirectory() + "/Library/Application Support/Claude/Cookies"
    nonisolated(unsafe) static var key: Data?

    /// Chromium safeStorage key: PBKDF2-SHA1 of the Keychain password, "saltysalt", 1003 rounds.
    static func storageKey() throws -> Data {
        if let key { return key }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        p.arguments = ["find-generic-password", "-s", "Claude Safe Storage", "-w"]
        let out = Pipe()
        p.standardOutput = out
        p.standardError = Pipe()
        try p.run()
        let pw = out.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        guard p.terminationStatus == 0 else { throw FetchError.keychain }
        let password = pw.filter { $0 != 0x0A }
        var derived = Data(count: 16)
        let salt = Data("saltysalt".utf8)
        let status = derived.withUnsafeMutableBytes { d in
            password.withUnsafeBytes { p in
                salt.withUnsafeBytes { s in
                    CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                                         p.baseAddress?.assumingMemoryBound(to: CChar.self), password.count,
                                         s.baseAddress?.assumingMemoryBound(to: UInt8.self), salt.count,
                                         CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1), 1003,
                                         d.baseAddress?.assumingMemoryBound(to: UInt8.self), 16)
                }
            }
        }
        guard status == kCCSuccess else { throw FetchError.keychain }
        key = derived
        return derived
    }

    static func decrypt(_ blob: Data, host: String, key: Data) -> String? {
        guard blob.count > 3, blob.prefix(3) == Data("v10".utf8) || blob.prefix(3) == Data("v11".utf8) else { return nil }
        let ct = blob.dropFirst(3)
        let iv = Data(repeating: 0x20, count: 16)
        var out = Data(count: ct.count + kCCBlockSizeAES128)
        var outLen = 0
        let cap = out.count
        let status = out.withUnsafeMutableBytes { o in
            ct.withUnsafeBytes { c in
                key.withUnsafeBytes { k in
                    iv.withUnsafeBytes { i in
                        CCCrypt(CCOperation(kCCDecrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionPKCS7Padding),
                                k.baseAddress, 16, i.baseAddress, c.baseAddress, ct.count, o.baseAddress, cap, &outLen)
                    }
                }
            }
        }
        guard status == kCCSuccess else { return nil }
        var pt = out.prefix(outLen)
        // Newer Chromium prefixes the plaintext with SHA256(host).
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        let h = Data(host.utf8)
        _ = h.withUnsafeBytes { CC_SHA256($0.baseAddress, CC_LONG(h.count), &hash) }
        if pt.count >= 32, Data(pt.prefix(32)) == Data(hash) { pt = pt.dropFirst(32) }
        return String(data: pt, encoding: .utf8)
    }

    static func cookies() throws -> [String: String] {
        let key = try storageKey()
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.copyItem(atPath: cookiesPath, toPath: tmp.path)
        defer { try? FileManager.default.removeItem(at: tmp) }

        var db: OpaquePointer?
        guard sqlite3_open_v2(tmp.path, &db, SQLITE_OPEN_READONLY, nil) == SQLITE_OK else { throw FetchError.notSignedIn }
        defer { sqlite3_close(db) }
        var stmt: OpaquePointer?
        let sql = "select host_key, name, encrypted_value from cookies where host_key like '%claude.ai'"
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { throw FetchError.notSignedIn }
        defer { sqlite3_finalize(stmt) }

        var result: [String: String] = [:]
        while sqlite3_step(stmt) == SQLITE_ROW {
            let host = String(cString: sqlite3_column_text(stmt, 0))
            let name = String(cString: sqlite3_column_text(stmt, 1))
            guard let bytes = sqlite3_column_blob(stmt, 2) else { continue }
            let blob = Data(bytes: bytes, count: Int(sqlite3_column_bytes(stmt, 2)))
            if let v = decrypt(blob, host: host, key: key) { result[name] = v }
        }
        return result
    }
}

// MARK: - claude.ai API

enum ClaudeAPI {
    static let limits: [(String, String, TimeInterval)] = [
        ("five_hour", "Session", 5 * 3600),
        ("seven_day", "Weekly", 7 * 86400),
        ("seven_day_opus", "Weekly · Opus", 7 * 86400),
        ("seven_day_sonnet", "Weekly · Sonnet", 7 * 86400),
    ]
    nonisolated(unsafe) static var emailCache: (session: String, email: String)?

    static func get(_ path: String, cookies: [String: String]) async throws -> [String: Any] {
        var req = URLRequest(url: URL(string: "https://claude.ai" + path)!, timeoutInterval: 15)
        req.setValue(cookies.map { "\($0.key)=\($0.value)" }.joined(separator: "; "), forHTTPHeaderField: "Cookie")
        req.setValue("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36",
                     forHTTPHeaderField: "User-Agent")
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        let (data, resp) = try await URLSession.shared.data(for: req)
        let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
        guard code == 200 else { throw FetchError.http(code) }
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw FetchError.badResponse }
        return json
    }

    static func parseDate(_ s: String?) -> Date? {
        guard let s else { return nil }
        // claude.ai sends microseconds, which ISO8601DateFormatter can't parse.
        let trimmed = s.replacingOccurrences(of: #"\.\d+"#, with: "", options: .regularExpression)
        return ISO8601DateFormatter().date(from: trimmed)
    }

    static func fetch() async throws -> Snapshot {
        let ck = try ClaudeDesktop.cookies()
        guard let session = ck["sessionKey"], let org = ck["lastActiveOrg"] else { throw FetchError.notSignedIn }
        let usage = try await get("/api/organizations/\(org)/usage", cookies: ck)

        // The account only changes with the session cookie, so look it up once per session.
        var email = emailCache?.session == session ? emailCache!.email : nil
        if email == nil {
            email = (try? await get("/api/account", cookies: ck))?["email_address"] as? String
            if let email { emailCache = (session, email) }
        }

        let limits = limits.compactMap { key, label, window -> Limit? in
            guard let l = usage[key] as? [String: Any], let used = l["utilization"] as? Double else { return nil }
            return Limit(id: key, label: label, used: used, resetsAt: parseDate(l["resets_at"] as? String), window: window)
        }
        return Snapshot(email: email ?? "Unknown account", limits: limits, updated: Date())
    }
}

// MARK: - State

@MainActor
final class UsageModel: ObservableObject {
    @Published var snapshot: Snapshot?
    @Published var error: String?
    @Published var loading = false
    var onChange: (() -> Void)?

    func refresh() {
        guard !loading else { return }
        loading = true
        Task {
            do {
                snapshot = try await ClaudeAPI.fetch()
                error = nil
            } catch {
                self.error = error.localizedDescription
            }
            loading = false
            onChange?()
        }
    }

    func refreshIfStale() {
        if snapshot.map({ Date().timeIntervalSince($0.updated) > 60 }) ?? true { refresh() }
    }
}

// MARK: - Menu bar icon

func statusIcon(session: Double?, weekly: Double?) -> NSImage {
    let img = NSImage(size: NSSize(width: 19, height: 15), flipped: true) { _ in
        for (y, left) in [(1.5, session), (8.5, weekly)] {
            let track = NSRect(x: 0.5, y: y, width: 18, height: 5)
            NSColor.black.withAlphaComponent(0.3).setFill()
            NSBezierPath(roundedRect: track, xRadius: 1.5, yRadius: 1.5).fill()
            if let left, left > 0 {
                var fill = track
                fill.size.width = max(3, 18 * left / 100)
                NSColor.black.setFill()
                NSBezierPath(roundedRect: fill, xRadius: 1.5, yRadius: 1.5).fill()
            }
        }
        return true
    }
    img.isTemplate = true
    return img
}

// MARK: - Popover UI

let claudeOrange = Color(red: 217 / 255, green: 119 / 255, blue: 87 / 255)

struct UsageBar: View {
    let used: Double
    let expected: Double?

    var body: some View {
        GeometryReader { g in
            ZStack(alignment: .leading) {
                Capsule().fill(Color.secondary.opacity(0.2))
                Capsule()
                    .fill(used >= 90 ? Color.red : claudeOrange)
                    .frame(width: max(used > 0 ? 6 : 0, g.size.width * used / 100))
                if let expected {
                    // Pace marker: where you'd be if spending evenly.
                    RoundedRectangle(cornerRadius: 1)
                        .fill(Color.primary.opacity(0.6))
                        .frame(width: 2, height: g.size.height + 4)
                        .offset(x: min(g.size.width - 2, max(0, g.size.width * expected / 100 - 1)))
                }
            }
        }
        .frame(height: 6)
    }
}

struct LimitView: View {
    let limit: Limit

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline) {
                Text(limit.label).font(.system(size: 13, weight: .semibold))
                Spacer()
                Text("\(Int(limit.left.rounded()))% left").font(.system(size: 12)).monospacedDigit()
            }
            UsageBar(used: limit.used, expected: limit.expected)
            HStack {
                if let r = limit.resetsAt { Text("Resets in \(duration(r.timeIntervalSinceNow))") }
                Spacer()
                if let p = limit.paceText {
                    Text("Pace: \(p)").foregroundStyle(limit.inDeficit ? Color.orange : Color.secondary)
                }
            }
            .font(.system(size: 11))
            .foregroundStyle(.secondary)
            if let proj = limit.projection {
                Text(proj).font(.system(size: 11)).foregroundStyle(.secondary)
            }
        }
    }
}

struct PopoverView: View {
    @ObservedObject var model: UsageModel
    @State private var launchAtLogin = SMAppService.mainApp.status == .enabled

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .firstTextBaseline) {
                Text("Claude").font(.system(size: 15, weight: .bold))
                Spacer()
                if model.loading { ProgressView().controlSize(.small) }
                else if let s = model.snapshot {
                    TimelineView(.periodic(from: .now, by: 30)) { _ in
                        Text(updatedText(s.updated)).font(.system(size: 11)).foregroundStyle(.secondary)
                    }
                }
            }
            if let s = model.snapshot {
                Label(s.email, systemImage: "person.crop.circle")
                    .font(.system(size: 12)).foregroundStyle(.secondary).padding(.top, -8)
            }
            if let e = model.error {
                Label(e, systemImage: "exclamationmark.triangle.fill")
                    .font(.system(size: 12)).foregroundStyle(.red).fixedSize(horizontal: false, vertical: true)
            }
            if let s = model.snapshot {
                ForEach(s.limits) { l in
                    Divider()
                    LimitView(limit: l)
                }
            } else if model.error == nil {
                Text("Loading…").foregroundStyle(.secondary)
            }
            Divider()
            VStack(alignment: .leading, spacing: 2) {
                MenuRow(title: "Refresh", icon: "arrow.clockwise") { model.refresh() }
                MenuRow(title: "Usage Dashboard", icon: "chart.bar") {
                    NSWorkspace.shared.open(URL(string: "https://claude.ai/settings/usage")!)
                }
                Toggle(isOn: $launchAtLogin) { Text("Launch at Login").font(.system(size: 13)) }
                    .toggleStyle(.checkbox).focusable(false).padding(.horizontal, 6).padding(.vertical, 3)
                    .onChange(of: launchAtLogin) { _, on in
                        try? on ? SMAppService.mainApp.register() : SMAppService.mainApp.unregister()
                        launchAtLogin = SMAppService.mainApp.status == .enabled
                    }
                MenuRow(title: "Quit", icon: "power") { NSApp.terminate(nil) }
            }
        }
        .padding(14)
        .frame(width: 300)
    }

    func updatedText(_ d: Date) -> String {
        let s = Int(Date().timeIntervalSince(d))
        return s < 60 ? "Updated just now" : "Updated \(s / 60)m ago"
    }
}

struct MenuRow: View {
    let title: String
    let icon: String
    let action: () -> Void
    @State private var hover = false

    var body: some View {
        Button(action: action) {
            HStack {
                Image(systemName: icon).frame(width: 16)
                Text(title)
                Spacer()
            }
            .font(.system(size: 13))
            .padding(.horizontal, 6).padding(.vertical, 4)
            .background(RoundedRectangle(cornerRadius: 5).fill(hover ? Color.secondary.opacity(0.15) : .clear))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .focusable(false)
        .onHover { hover = $0 }
    }
}

// MARK: - App

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    let model = UsageModel()
    let popover = NSPopover()
    var item: NSStatusItem!
    var timer: Timer?

    func applicationDidFinishLaunching(_ note: Notification) {
        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        item.autosaveName = "ClaudeBar"  // keeps the position after you Cmd-drag the icon
        item.button?.image = statusIcon(session: nil, weekly: nil)
        item.button?.target = self
        item.button?.action = #selector(toggle)

        popover.behavior = .transient
        popover.animates = false
        popover.contentViewController = NSHostingController(rootView: PopoverView(model: model))

        model.onChange = { [weak self] in self?.updateIcon() }
        model.refresh()
        if CommandLine.arguments.contains("--open") {  // for screenshots / testing
            DispatchQueue.main.asyncAfter(deadline: .now() + 2) { self.toggle() }
        }
        // claude.ai allows ~20-25 usage checks per 10 minutes per account; every 2 minutes is plenty.
        timer = Timer.scheduledTimer(withTimeInterval: 120, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.model.refresh() }
        }
    }

    func updateIcon() {
        let limits = model.snapshot?.limits ?? []
        let left = { (id: String) in limits.first { $0.id == id }?.left }
        item.button?.image = statusIcon(session: left("five_hour"), weekly: left("seven_day"))
        item.button?.toolTip = model.error ?? limits.prefix(2)
            .map { "\($0.label): \(Int($0.left.rounded()))% left" }.joined(separator: "\n")
    }

    @objc func toggle() {
        if popover.isShown {
            popover.performClose(nil)
        } else if let button = item.button {
            model.refreshIfStale()
            popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
            popover.contentViewController?.view.window?.makeKey()
            NSApp.activate()
        }
    }
}

@main
enum Main {
    static func main() {
        let app = NSApplication.shared
        let delegate = MainActor.assumeIsolated { AppDelegate() }
        app.delegate = delegate
        app.setActivationPolicy(.accessory)
        withExtendedLifetime(delegate) { app.run() }
    }
}
