// Copyright (c) 2026, LunLink contributors
// SPDX-License-Identifier: BSD-2-Clause

import Combine
import SwiftUI

@main
struct LunLinkApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var state = AppState()
    @AppStorage(MenuBarItem.key) private var showMenuBarItem = true

    init() {
        // The application always starts with its window.  Left to itself,
        // the system brings back the windows that an application had when
        // it was last cut short (by a crash or a power failure, say), which
        // is none at all if the application was down to its menu bar item.
        UserDefaults.standard.register(defaults: ["ApplePersistenceIgnoreState": true])
    }

    var body: some Scene {
        Window("LunLink", id: MainWindow.id) {
            ContentView()
                .environmentObject(state)
        }
        .defaultSize(width: 900, height: 620)
        .commands {
            CommandGroup(replacing: .newItem) {
                Button("Add Target…") { state.showingAddTarget = true }
                    .keyboardShortcut("n")
            }
            CommandGroup(after: .toolbar) {
                Button("Refresh") { Task { await state.refresh() } }
                    .keyboardShortcut("r")
            }
        }

        Settings {
            SettingsView()
                .environmentObject(state)
        }

        MenuBarExtra(isInserted: $showMenuBarItem) {
            MenuBarContent()
                .environmentObject(state)
        } label: {
            MenuBarLabel()
                .environmentObject(state)
        }
    }
}

/// The item in the menu bar, which the user may do without.
enum MenuBarItem {
    static let key = "showMenuBarItem"

    static var isShown: Bool {
        UserDefaults.standard.object(forKey: key) == nil || UserDefaults.standard.bool(forKey: key)
    }
}

/// The presence of the application in the Dock.  The application is there
/// while it has a window open; once the window is closed, the item in the
/// menu bar is all that remains of it.
@MainActor
enum DockIcon {
    /// Whether a window of the application is open (alerts aside).
    static var hasWindows: Bool {
        NSApp.windows.contains { $0.isVisible && $0.styleMask.contains(.titled) && !($0 is NSPanel) }
    }

    /// Puts the application in the Dock or takes it out, as befits its state.
    /// Without an item in the menu bar the Dock is the only place it has.
    static func update() {
        if hasWindows || !MenuBarItem.isShown {
            show()
        } else if NSApp.activationPolicy() != .accessory {
            NSApp.setActivationPolicy(.accessory)
        }
    }

    /// Puts the application in the Dock, ahead of opening a window.
    static func show() {
        guard NSApp.activationPolicy() != .regular else { return }

        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var observers: [NSObjectProtocol] = []

    func applicationDidFinishLaunching(_ notification: Notification) {
        #if DEBUG
        signal(SIGUSR1, SIG_IGN)    // see DebugSnapshot
        #endif

        func observe(_ name: Notification.Name, _ action: @escaping @MainActor () -> Void) {
            observers.append(NotificationCenter.default.addObserver(forName: name, object: nil, queue: .main) { _ in
                // A window that is about to close still counts as open, so
                // the matter is looked into once the dust has settled
                RunLoop.main.perform {
                    MainActor.assumeIsolated(action)
                }
            })
        }

        // Only a window that closes takes the application out of the Dock.
        // (While the application starts it has no window yet, which is no
        // reason to leave: its window would not come up any more.)
        observe(NSWindow.willCloseNotification) { DockIcon.update() }
        observe(NSWindow.didBecomeMainNotification) { DockIcon.show() }

        // Once the item in the menu bar is turned off, the Dock is all there is
        observe(UserDefaults.didChangeNotification) {
            if !MenuBarItem.isShown { DockIcon.show() }
        }
    }

    /// The application was opened while it was running already (from the
    /// Finder, say), which calls for its window.
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows: Bool) -> Bool {
        MainActor.assumeIsolated {
            // The window is opened from the menu bar item if there is one,
            // and by SwiftUI otherwise
            guard !hasVisibleWindows, MenuBarItem.isShown else {
                DockIcon.show()
                return true
            }
            MainWindow.requests.send()
            return false
        }
    }

    /// Closing the window leaves the application in the menu bar, from where
    /// the window can be opened again and the application can be quit.
    /// Without an item in the menu bar there is nowhere for it to stay.
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        !MenuBarItem.isShown
    }
}

/// A target in the menu of the menu bar item.  The item says what state the
/// target is in; what to do about it is spelled out a level below, since a
/// slip of the hand in a menu ought not to cost anyone their disks.
private struct TargetMenu: View {
    @EnvironmentObject private var state: AppState
    let target: Target
    let busy: Bool

    var body: some View {
        // (A title that is not a literal is shown as it is.)
        let title = "\(target.displayName) — \(status)"

        Menu {
            if target.connected {
                Button("Disconnect") { state.confirmDisconnect(target) }
            } else {
                Button("Connect") { state.connect(target) }
            }
        } label: {
            Label(title, systemImage: symbol)
        }
        .disabled(busy)
    }

    private var status: String {
        if busy {
            return target.connected ? String(localized: "Disconnecting…") : String(localized: "Connecting…")
        }
        guard let session = target.session else { return String(localized: "Not connected") }
        return session.recovering ? String(localized: "Reconnecting…") : String(localized: "Connected")
    }

    private var symbol: String {
        if busy { return "ellipsis.circle" }
        guard let session = target.session else { return "circle" }
        return session.recovering ? "exclamationmark.triangle.fill" : "checkmark.circle.fill"
    }
}

/// The main window, which may be closed while the application runs on.
enum MainWindow {
    static let id = "main"

    /// Requests for the window to be opened, which only a view can do (see
    /// MenuBarLabel).
    static let requests = PassthroughSubject<Void, Never>()

    @MainActor
    static var isOpen: Bool {
        NSApp.windows.contains { $0.isVisible && ($0.identifier?.rawValue == id || $0.frameAutosaveName == id) }
    }
}

/// The icon of the menu bar item.  Unlike the menu and the windows it is
/// there at all times, which makes it the place from which to open the main
/// window on request.
private struct MenuBarLabel: View {
    @EnvironmentObject private var state: AppState
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Image(systemName: state.connectedCount > 0 ? "externaldrive.fill.badge.checkmark" : "externaldrive")
            .onReceive(MainWindow.requests) {
                DockIcon.show()
                openWindow(id: MainWindow.id)

                // Only once it has a window does the application come to the front
                NSApp.activate(ignoringOtherApps: true)
            }
    }
}

/// The menu of the menu bar item: targets can be connected and disconnected
/// without opening the main window.
private struct MenuBarContent: View {
    @EnvironmentObject private var state: AppState

    var body: some View {
        // (A line of text makes for a heading without the separators that
        // a section would surround itself with.)
        Text(state.targets.isEmpty ? "No Targets" : "Targets")

        ForEach(state.targets) { target in
            TargetMenu(target: target, busy: state.busyTargets.contains(target.iqn))
        }

        Divider()

        Button("Open LunLink") {
            MainWindow.requests.send()
        }

        Button("Quit") {
            NSApp.terminate(nil)
        }
        .keyboardShortcut("q")
    }
}
