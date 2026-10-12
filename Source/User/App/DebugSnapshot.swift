// Copyright (c) 2026, LunLink contributors
// SPDX-License-Identifier: BSD-2-Clause

#if DEBUG
import AppKit

/// A development aid: has the application draw its own windows into image
/// files, so that the user interface can be inspected without access to
/// the screen.  Only present in builds made with `make app DEBUG=1`.
///
///   ISCSI_APP_SNAPSHOT_DIR   directory for the images; upon the signal
///                            SIGUSR1 every visible window is written there
///   ISCSI_APP_DEBUG_ACTIONS  comma-separated actions to carry out shortly
///                            after launch: "add-target", "settings",
///                            "settings-tab-<n>", "language=<en|zh-Hans|>",
///                            "connect[=<seconds>]" (connects the first
///                            target), "disconnect=<seconds>" (asks to
///                            disconnect the first connected target),
///                            "close-window=<seconds>" (closes the main
///                            window the way its close button does),
///                            "reopen=<seconds>" (what opening the
///                            application once more amounts to),
///                            "show=<seconds>" (what "Open" in the menu of
///                            the menu bar item does), "quit=<seconds>"
///
/// Next to the images, state.txt says whether the application is in the Dock.
///                            "confirm=<seconds>" (presses the default
///                            button of an alert that many seconds later),
///                            "cancel=<seconds>" (presses its cancel button)
@MainActor
enum DebugSnapshot {
    private static var source: DispatchSourceSignal?

    static func install(state: AppState) {
        let environment = ProcessInfo.processInfo.environment

        guard source == nil, let directory = environment["ISCSI_APP_SNAPSHOT_DIR"] else { return }

        signal(SIGUSR1, SIG_IGN)
        let source = DispatchSource.makeSignalSource(signal: SIGUSR1, queue: .main)
        source.setEventHandler { MainActor.assumeIsolated { snapshot(to: directory) } }
        source.resume()
        self.source = source

        let actions = (environment["ISCSI_APP_DEBUG_ACTIONS"] ?? "").split(separator: ",").map(String.init)

        DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
            if actions.contains("add-target") {
                state.showingAddTarget = true
            }
            // The settings window is opened the way the user would: through
            // the item of the application menu (the one with the comma key)
            if actions.contains("settings"),
               let item = NSApp.mainMenu?.items.first?.submenu?.items.first(where: { $0.keyEquivalent == "," }),
               let action = item.action {
                NSApp.sendAction(action, to: item.target, from: item)
            }

            if let delay = actions.first(where: { $0.hasPrefix("close-window=") }).flatMap({ Double($0.dropFirst(13)) }) {
                DispatchQueue.main.asyncAfter(deadline: .now() + delay) {
                    NSApp.windows.first { $0.isVisible && $0.canBecomeMain }?.performClose(nil)
                }
            }

            if let delay = actions.first(where: { $0.hasPrefix("reopen=") }).flatMap({ Double($0.dropFirst(7)) }) {
                DispatchQueue.main.asyncAfter(deadline: .now() + delay) {
                    let event = NSAppleEventDescriptor(eventClass: AEEventClass(kCoreEventClass),
                                                       eventID: AEEventID(kAEReopenApplication),
                                                       targetDescriptor: .currentProcess(),
                                                       returnID: AEReturnID(kAutoGenerateReturnID),
                                                       transactionID: AETransactionID(kAnyTransactionID))
                    _ = try? event.sendEvent(options: .noReply, timeout: 5)
                }
            }

            if let delay = actions.first(where: { $0.hasPrefix("disconnect=") }).flatMap({ Double($0.dropFirst(11)) }) {
                DispatchQueue.main.asyncAfter(deadline: .now() + delay) {
                    if let target = state.targets.first(where: \.connected) { state.confirmDisconnect(target) }
                }
            }

            if let delay = actions.first(where: { $0.hasPrefix("show=") }).flatMap({ Double($0.dropFirst(5)) }) {
                DispatchQueue.main.asyncAfter(deadline: .now() + delay) { MainWindow.requests.send() }
            }

            if let delay = actions.first(where: { $0.hasPrefix("quit=") }).flatMap({ Double($0.dropFirst(5)) }) {
                DispatchQueue.main.asyncAfter(deadline: .now() + delay) { NSApp.terminate(nil) }
            }

            if let action = actions.first(where: { $0 == "connect" || $0.hasPrefix("connect=") }) {
                DispatchQueue.main.asyncAfter(deadline: .now() + (Double(action.dropFirst(8)) ?? 0)) {
                    if let target = state.targets.first { state.connect(target) }
                }
            }

            // Chooses a language the way the picker of the settings does
            if let language = actions.first(where: { $0.hasPrefix("language=") })
                .flatMap({ AppLanguage(rawValue: String($0.dropFirst(9))) }) {
                state.setLanguage(language)
            }

            if let delay = actions.first(where: { $0.hasPrefix("confirm=") }).flatMap({ Double($0.dropFirst(8)) }) {
                DispatchQueue.main.asyncAfter(deadline: .now() + delay) {
                    NSApp.modalWindow?.defaultButtonCell?.performClick(nil)
                }
            }

            // Presses the button of an alert that the escape key stands for
            if let delay = actions.first(where: { $0.hasPrefix("cancel=") }).flatMap({ Double($0.dropFirst(7)) }) {
                DispatchQueue.main.asyncAfter(deadline: .now() + delay) {
                    let buttons = NSApp.modalWindow?.contentView?.subviews.compactMap { $0 as? NSButton } ?? []
                    buttons.first { $0.keyEquivalent == "\u{1b}" }?.performClick(nil)
                }
            }

            // Selects a tab of the settings window ("settings-tab-1", ...)
            if let tab = actions.first(where: { $0.hasPrefix("settings-tab-") }).flatMap({ Int($0.dropFirst(13)) }) {
                DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
                    for window in NSApp.windows {
                        if let toolbar = window.toolbar, toolbar.items.count > tab,
                           let action = toolbar.items[tab].action {
                            NSApp.sendAction(action, to: toolbar.items[tab].target, from: toolbar.items[tab])
                        }
                    }
                }
            }
        }
    }

    private typealias CaptureFunction = @convention(c) (CGRect, UInt32, UInt32, UInt32) -> Unmanaged<CGImage>?

    /// Captures a window of this application as the window server shows it
    /// (which, unlike drawing the views, includes translucent materials).
    private static func capture(_ window: NSWindow) -> Data? {
        // The function is no longer declared by the SDK, yet still present
        guard let symbol = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "CGWindowListCreateImage") else { return nil }

        let function = unsafeBitCast(symbol, to: CaptureFunction.self)
        let includingWindow: UInt32 = 1 << 3
        let boundsIgnoreFraming: UInt32 = 1 << 0

        guard let image = function(.null, includingWindow, UInt32(window.windowNumber), boundsIgnoreFraming)?
            .takeRetainedValue(), image.width > 50 else { return nil }

        return NSBitmapImageRep(cgImage: image).representation(using: .png, properties: [:])
    }

    /// Lists the items of the menu of the menu bar item, which no image of
    /// a window shows.
    private static func menuReport() -> String {
        var lines: [String] = []

        func list(_ menu: NSMenu, _ indent: String) {
            menu.update()
            menu.delegate?.menuNeedsUpdate?(menu)

            for item in menu.items {
                if item.isSeparatorItem {
                    lines.append(indent + "----" + (item.isHidden ? " (hidden)" : ""))
                } else {
                    var flags = (item.isEnabled ? "" : " (disabled)") + (item.image != nil ? " [image]" : "")
                    if #available(macOS 14.0, *), item.isSectionHeader { flags += " [header]" }
                    lines.append(indent + item.title + flags)
                    if let submenu = item.submenu { list(submenu, indent + "    ") }
                }
            }
        }

        for window in NSApp.windows {
            guard String(describing: type(of: window)).contains("StatusBar"),
                  let item = window.value(forKey: "statusItem") as? NSStatusItem, let menu = item.menu else { continue }
            lines.append("menu:")
            list(menu, "    ")
        }
        return lines.joined(separator: "\n") + "\n"
    }

    private static func snapshot(to directory: String) {
        try? FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)

        let policy = NSApp.activationPolicy() == .regular ? "regular" : NSApp.activationPolicy() == .accessory ? "accessory" : "prohibited"
        let ownsMenuBar = NSWorkspace.shared.menuBarOwningApplication?.processIdentifier == getpid()
        let report = "policy=\(policy) windows=\(DockIcon.hasWindows) mainWindow=\(MainWindow.isOpen) active=\(NSApp.isActive) ownsMenuBar=\(ownsMenuBar)\n"
        try? (report + menuReport()).write(toFile: directory + "/state.txt", atomically: true, encoding: .utf8)

        for (index, window) in NSApp.windows.enumerated() where window.isVisible {
            // The frame view includes the title bar and the toolbar
            guard let view = window.contentView?.superview ?? window.contentView,
                  view.bounds.width > 50, view.bounds.height > 50 else { continue }

            var data = capture(window)
            var name = "window-\(index).png"

            if data == nil, let bitmap = view.bitmapImageRepForCachingDisplay(in: view.bounds) {
                view.cacheDisplay(in: view.bounds, to: bitmap)
                data = bitmap.representation(using: .png, properties: [:])
                name = "window-\(index)-drawn.png"
            }

            if let data {
                try? data.write(to: URL(fileURLWithPath: directory).appendingPathComponent(name))
            }
        }
    }
}
#endif
