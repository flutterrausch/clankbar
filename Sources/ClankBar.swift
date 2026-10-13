// ClankBar: menu bar app showing the 5-hour and weekly limits of whatever
// account the Claude desktop app is signed into. Reads the app's claude.ai cookies
// (decrypted with the "Claude Safe Storage" Keychain item) on every refresh, so it
// follows account switches. Visuals follow CodexBar: two stacked "remaining" bars.

import AppKit
import CommonCrypto
import ServiceManagement
import SQLite3
import SwiftUI

// MARK: - Model

struct Limit: Identifiable, Codable {
    let id: String
    let label: String
    let used: Double
    let resetsAt: Date?
    let window: TimeInterval
    /// Set on a stored limit whose window has reset since it was last read.
    var wasResetAt: Date? = nil

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

    /// Only set when the average rate so far would hit the limit before the reset.
    var runsOut: String? {
        guard let resetsAt else { return nil }
        let elapsed = window - resetsAt.timeIntervalSinceNow
        guard used > 0, elapsed > 300, inDeficit else { return nil }  // keep in line with the pace text
        let runout = elapsed * (100 - used) / used
        guard runout < resetsAt.timeIntervalSinceNow else { return nil }
        return "Runs out in \(relative(Date(timeIntervalSinceNow: runout)))"
    }

    /// A stored value brought up to date: once the reset time has passed, the window is empty again.
    func aged() -> Limit {
        guard let resetsAt, resetsAt <= Date() else { return self }
        return Limit(id: id, label: label, used: 0, resetsAt: nil, window: window, wasResetAt: resetsAt)
    }
}

struct Snapshot: Codable {
    let email: String
    let limits: [Limit]
    let updated: Date
}

/// Last-seen numbers per account (no credentials), so accounts that aren't active
/// in the desktop app right now can still be shown.
enum AccountStore {
    static let key = "accounts"

    static func all() -> [String: Snapshot] {
        guard let data = UserDefaults.standard.data(forKey: key) else { return [:] }
        return (try? JSONDecoder().decode([String: Snapshot].self, from: data)) ?? [:]
    }

    static func save(_ s: Snapshot) {
        var accounts = all()
        accounts[s.email] = s
        if let data = try? JSONEncoder().encode(accounts) { UserDefaults.standard.set(data, forKey: key) }
    }

    static func others(than email: String?) -> [Snapshot] {
        all().values.filter { $0.email != email }.sorted { $0.email < $1.email }
    }
}

/// "12:49", or "Thu 19:59" when it's not today.
func clock(_ date: Date) -> String {
    let f = DateFormatter()
    f.setLocalizedDateFormatFromTemplate(Calendar.current.isDateInToday(date) ? "HHmm" : "EEEHHmm")
    return f.string(from: date)
}

/// "4h 1m (12:49)", or "2d 11h (Thu 19:59)" when it's not today.
func relative(_ date: Date) -> String {
    "\(duration(date.timeIntervalSinceNow)) (\(clock(date)))"
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
    static let unknownEmail = "Unknown account"
    nonisolated(unsafe) static var emailCache: (session: String, email: String)?

    static func get(_ path: String, cookies: [String: String]) async throws -> [String: Any] {
        guard let json = try await getJSON(path, cookies: cookies) as? [String: Any] else { throw FetchError.badResponse }
        return json
    }

    static func getJSON(_ path: String, cookies: [String: String]) async throws -> Any {
        var req = URLRequest(url: URL(string: "https://claude.ai" + path)!, timeoutInterval: 15)
        req.setValue(cookies.map { "\($0.key)=\($0.value)" }.joined(separator: "; "), forHTTPHeaderField: "Cookie")
        req.setValue("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36",
                     forHTTPHeaderField: "User-Agent")
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        let (data, resp) = try await URLSession.shared.data(for: req)
        let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
        guard code == 200 else { throw FetchError.http(code) }
        return try JSONSerialization.jsonObject(with: data)
    }

    /// The account's chat (Pro/Max) organization, for when lastActiveOrg doesn't belong to the session.
    static func chatOrg(cookies: [String: String]) async throws -> String {
        let orgs = try await getJSON("/api/organizations", cookies: cookies) as? [[String: Any]] ?? []
        let chat = orgs.first { ($0["capabilities"] as? [String])?.contains("chat") == true } ?? orgs.first
        guard let id = chat?["uuid"] as? String else { throw FetchError.badResponse }
        return id
    }

    static func parseDate(_ s: String?) -> Date? {
        guard let s else { return nil }
        // claude.ai sends microseconds, which ISO8601DateFormatter can't parse.
        let trimmed = s.replacingOccurrences(of: #"\.\d+"#, with: "", options: .regularExpression)
        // Resets sit on whole minutes but can arrive as e.g. 12:09:59.98; round like the desktop app does.
        return ISO8601DateFormatter().date(from: trimmed).map { Date(timeIntervalSince1970: ($0.timeIntervalSince1970 / 60).rounded() * 60) }
    }

    static func fetch() async throws -> Snapshot {
        let ck = try ClaudeDesktop.cookies()
        guard let session = ck["sessionKey"] else { throw FetchError.notSignedIn }
        // Right after an account switch, lastActiveOrg can still name the previous account's org.
        var usage: [String: Any]
        do {
            guard let org = ck["lastActiveOrg"] else { throw FetchError.http(403) }
            usage = try await get("/api/organizations/\(org)/usage", cookies: ck)
        } catch FetchError.http(let code) where code == 403 || code == 404 {
            usage = try await get("/api/organizations/\(try await chatOrg(cookies: ck))/usage", cookies: ck)
        }

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
        return Snapshot(email: email ?? unknownEmail, limits: limits, updated: Date())
    }
}

// MARK: - State

@MainActor
final class UsageModel: ObservableObject {
    @Published var snapshot: Snapshot?
    @Published var error: String?
    @Published var notice: String?
    @Published var others = AccountStore.others(than: nil)
    @Published var loading = false
    var onChange: (() -> Void)?
    private var retries = 0

    func refresh() {
        guard !loading else { return }
        loading = true
        Task {
            do {
                let s = try await ClaudeAPI.fetch()
                snapshot = s
                if s.email != ClaudeAPI.unknownEmail { AccountStore.save(s) }
                others = AccountStore.others(than: s.email)
                error = nil
                notice = nil
                retries = 0
            } catch {
                // While the desktop app switches accounts its cookies are briefly stale or
                // half-written. Retry quietly a few times before calling it an error.
                if Self.isTransient(error), retries < 6 {
                    retries += 1
                    notice = "Waiting for Claude desktop to finish switching accounts…"
                    DispatchQueue.main.asyncAfter(deadline: .now() + 10) { [weak self] in self?.refresh() }
                } else {
                    self.error = error.localizedDescription
                    notice = nil
                    retries = 0
                }
            }
            loading = false
            onChange?()
        }
    }

    static func isTransient(_ error: Error) -> Bool {
        switch error as? FetchError {
        case .http(let code): code == 401 || code == 403
        case .notSignedIn: true
        default: false
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

/// Fills with what's left, like the menu bar icon, so it shrinks as you use the limit.
struct UsageBar: View {
    let left: Double
    /// What would be left if you'd spent evenly so far. Fill ending left of it means you're behind pace.
    let expectedLeft: Double?

    var body: some View {
        GeometryReader { g in
            ZStack(alignment: .leading) {
                Capsule().fill(Color.secondary.opacity(0.2))
                Capsule()
                    .fill(left <= 10 ? Color.red : claudeOrange)
                    .frame(width: max(left > 0 ? 6 : 0, g.size.width * left / 100))
                if let expectedLeft {
                    RoundedRectangle(cornerRadius: 1)
                        .fill(Color.primary.opacity(0.6))
                        .frame(width: 2, height: g.size.height + 4)
                        .offset(x: min(g.size.width - 2, max(0, g.size.width * expectedLeft / 100 - 1)))
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
            UsageBar(left: limit.left, expectedLeft: limit.expected.map { 100 - $0 })
            HStack {
                if let r = limit.resetsAt { Text("Reset \(relative(r))") }
                else if let r = limit.wasResetAt { Text("Reset at \(clock(r))") }
                else { Text("Not started yet") }
                Spacer()
                if let p = limit.paceText {
                    Text(p).foregroundStyle(limit.inDeficit ? Color.orange : Color.secondary)
                }
            }
            .font(.system(size: 11))
            .foregroundStyle(.secondary)
            if let r = limit.runsOut {
                Text(r).font(.system(size: 11)).foregroundStyle(.orange)
            }
        }
    }
}

/// An account that isn't active in the desktop app, from its last-seen numbers: same layout, dimmed.
struct OtherAccountView: View {
    let snapshot: Snapshot

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .firstTextBaseline) {
                Label(snapshot.email, systemImage: "person.crop.circle").font(.system(size: 12))
                Spacer()
                Text("as of \(clock(snapshot.updated))").font(.system(size: 11))
            }
            .foregroundStyle(.secondary)
            ForEach(snapshot.limits.map { $0.aged() }) { l in
                LimitView(limit: l)
            }
        }
        .opacity(0.55)
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
            if let n = model.notice {
                Label(n, systemImage: "arrow.triangle.2.circlepath")
                    .font(.system(size: 12)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            } else if let e = model.error {
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
            ForEach(model.others, id: \.email) { o in
                Divider()
                OtherAccountView(snapshot: o)
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

/// Borderless dropdown panel. Positioned by hand below the menu bar instead of an
/// NSPopover, which anchors to the status button and lands on top of the menu bar
/// when a menu bar manager (Hidden Bar) has collapsed the icon.
final class DropdownPanel: NSPanel {
    override var canBecomeKey: Bool { true }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    let model = UsageModel()
    var item: NSStatusItem!
    var panel: DropdownPanel!
    var host: NSHostingView<PopoverView>!
    var timer: Timer?
    var outsideClick: Any?
    var escapeKey: Any?

    func applicationDidFinishLaunching(_ note: Notification) {
        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        item.autosaveName = "ClankBar"  // keeps the position after you Cmd-drag the icon
        item.button?.image = statusIcon(session: nil, weekly: nil)
        item.button?.target = self
        item.button?.action = #selector(toggle)

        host = NSHostingView(rootView: PopoverView(model: model))
        host.translatesAutoresizingMaskIntoConstraints = false
        let fx = NSVisualEffectView()
        fx.material = .popover
        fx.state = .active
        fx.wantsLayer = true
        fx.layer?.cornerRadius = 10
        fx.layer?.masksToBounds = true
        fx.addSubview(host)
        NSLayoutConstraint.activate([
            host.leadingAnchor.constraint(equalTo: fx.leadingAnchor),
            host.trailingAnchor.constraint(equalTo: fx.trailingAnchor),
            host.topAnchor.constraint(equalTo: fx.topAnchor),
            host.bottomAnchor.constraint(equalTo: fx.bottomAnchor),
        ])
        panel = DropdownPanel(contentRect: .zero, styleMask: [.borderless, .nonactivatingPanel],
                              backing: .buffered, defer: true)
        panel.isOpaque = false
        panel.backgroundColor = .clear
        panel.hasShadow = true
        panel.level = .popUpMenu
        panel.collectionBehavior = [.canJoinAllSpaces, .transient]
        panel.contentView = fx

        model.onChange = { [weak self] in
            self?.updateIcon()
            if self?.panel.isVisible == true { self?.layoutPanel() }
        }
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

    /// Just below the menu bar, centered under the icon when it's on screen, else at the right edge.
    func layoutPanel() {
        let size = host.fittingSize
        let iconFrame = item.button?.window?.frame
        let screen = item.button?.window?.screen ?? NSScreen.main!
        let area = screen.visibleFrame
        var x = area.maxX - size.width - 8
        if let f = iconFrame, f.minX >= screen.frame.minX, f.maxX <= screen.frame.maxX {
            x = f.midX - size.width / 2
        }
        x = min(max(x, area.minX + 8), area.maxX - size.width - 8)
        panel.setFrame(NSRect(x: x, y: area.maxY - 4 - size.height, width: size.width, height: size.height), display: true)
    }

    @objc func toggle() {
        panel.isVisible ? close() : open()
    }

    func open() {
        model.refreshIfStale()
        layoutPanel()
        panel.orderFrontRegardless()
        panel.makeKey()
        outsideClick = NSEvent.addGlobalMonitorForEvents(matching: [.leftMouseDown, .rightMouseDown]) { [weak self] _ in
            Task { @MainActor in self?.close() }
        }
        escapeKey = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { [weak self] e in
            if e.keyCode == 53 { self?.close(); return nil }
            return e
        }
    }

    func close() {
        panel.orderOut(nil)
        if let m = outsideClick { NSEvent.removeMonitor(m); outsideClick = nil }
        if let m = escapeKey { NSEvent.removeMonitor(m); escapeKey = nil }
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
