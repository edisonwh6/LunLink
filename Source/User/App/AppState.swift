// Copyright (c) 2026, LunLink contributors
// SPDX-License-Identifier: BSD-2-Clause

import AppKit
import SwiftUI

/// The state of the application: a periodically refreshed snapshot of the
/// initiator, plus the operations that the user interface offers.
@MainActor
final class AppState: ObservableObject {
    @Published private(set) var snapshot = Snapshot()
    @Published private(set) var layouts: [String: DiskLayout] = [:]
    @Published private(set) var loaded = false

    /// Targets (by name) and disks (by BSD name) with an operation underway.
    @Published private(set) var busyTargets: Set<String> = []
    @Published private(set) var busyDisks: Set<String> = []

    @Published var selection: String?
    @Published var showingAddTarget = false

    /// An error for the main window to present.  Without that window (the
    /// application may be down to its item in the menu bar, from where
    /// targets are connected and disconnected) the error is presented here.
    @Published var error: OperationError? {
        didSet {
            guard let error, !MainWindow.isOpen else { return }
            self.error = nil

            RunLoop.main.perform {
                MainActor.assumeIsolated {
                    let alert = NSAlert()
                    alert.alertStyle = .warning
                    alert.messageText = error.title
                    alert.informativeText = error.message
                    alert.addButton(withTitle: String(localized: "OK"))

                    NSApp.activate(ignoringOtherApps: true)
                    alert.runModal()
                }
            }
        }
    }

    private let daemon = DaemonClient.shared
    private var timer: Timer?
    private var refreshing = false

    init() {
        timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
            Task { @MainActor in await self?.refresh() }
        }
        Task { await refresh() }
    }

    var targets: [Target] { snapshot.targets }

    func target(_ iqn: String?) -> Target? {
        guard let iqn else { return nil }
        return snapshot.targets.first { $0.iqn == iqn }
    }

    var connectedCount: Int { snapshot.targets.filter(\.connected).count }

    // MARK: Refreshing

    func refresh() async {
        guard !refreshing else { return }
        refreshing = true
        defer { refreshing = false }

        let snapshot = await daemon.snapshot()
        let disks = Set(snapshot.targets.flatMap(\.disks).compactMap(\.bsdName))
        let layouts = await DiskUtility.layouts(of: disks)

        if snapshot != self.snapshot { self.snapshot = snapshot }
        if layouts != self.layouts { self.layouts = layouts }
        loaded = true

        if selection == nil || target(selection) == nil {
            selection = snapshot.targets.first?.iqn
        }
    }

    // MARK: Errors

    private func describe(_ code: Int32) -> String {
        switch code {
        case ENOTCONN: return String(localized: "The iSCSI daemon is not running.")
        case EBUSY: return String(localized: "The resource is in use.")
        case EEXIST: return String(localized: "The item exists already.")
        case EINVAL: return String(localized: "The name is not a valid IQN or EUI-64 identifier.")
        case EDESTADDRREQ: return String(localized: "The address is not valid.")
        case ETIMEDOUT: return String(localized: "The server did not respond in time.")
        case ECONNREFUSED: return String(localized: "The server refused the connection. Check the address and port, and that the iSCSI service is enabled on the server.")
        case ENETUNREACH, EHOSTDOWN: return String(localized: "The server cannot be reached. Check the address and your network connection.")
        case EHOSTUNREACH:
            // What macOS reports, too, if access to the local network was not granted
            return String(localized: "The server cannot be reached. Check the address and your network connection.") + "\n" +
                   String(localized: "If the server is on your local network, make sure that LunLink is allowed under Privacy & Security → Local Network in System Settings.")
        case ECONNRESET: return String(localized: "The server closed the connection during login. It may require CHAP authentication, or may not permit this initiator to access the target.")
        case EAUTH: return String(localized: "The server rejected the login. Check the CHAP user name and password.")
        default: return String(cString: strerror(code))
        }
    }

    private func report(_ title: String, _ code: Int32, status: Int32? = nil) {
        var message = describe(code)

        // The response of the target says more than the error code
        if let status, status != 0, status < 0x1000 {
            let description = translated(DaemonClient.loginStatusDescription(status))
            if !description.isEmpty && code != ECONNRESET {
                message = String(localized: "The server responded: \(description)")
                if status == 0x0201 || status == 0x0202 {
                    message += "\n" + String(localized: "Check the CHAP user name and password, and that the server permits this initiator to access the target.")
                }
            }
        }
        error = OperationError(title: title, message: message)
    }

    // MARK: Sessions

    func connect(_ target: Target) {
        guard !busyTargets.contains(target.iqn) else { return }
        busyTargets.insert(target.iqn)

        Task {
            let result = await daemon.login(target.iqn)
            busyTargets.remove(target.iqn)

            if result.error != 0 && result.error != EEXIST {
                report(String(localized: "Could not connect to “\(target.displayName)”"), result.error, status: result.status)
            }
            await refresh()
        }
    }

    /// Asks whether to disconnect a target, then does so.  Disconnecting
    /// takes the disks of the target away, which a slip of the hand should
    /// not bring about.
    /// - Parameter force: disconnect even if volumes are in use.
    func confirmDisconnect(_ target: Target, force: Bool = false) {
        guard !busyTargets.contains(target.iqn) else { return }

        // (The run loop is asked rather than the main queue, which would be
        // held up for as long as the alert is open.)
        RunLoop.main.perform {
            MainActor.assumeIsolated {
                let alert = NSAlert()
                alert.alertStyle = .warning

                if force {
                    alert.messageText = String(localized: "Disconnect “\(target.displayName)” even if its volumes are in use?")
                    alert.informativeText = String(localized: "Data that has not been written yet will be lost.")
                    alert.addButton(withTitle: String(localized: "Disconnect Anyway"))
                    alert.buttons.first?.hasDestructiveAction = true
                } else {
                    alert.messageText = String(localized: "Disconnect “\(target.displayName)”?")
                    alert.informativeText = String(localized: "The volumes on its disks will be unmounted.")
                    alert.addButton(withTitle: String(localized: "Disconnect"))
                }
                alert.addButton(withTitle: String(localized: "Cancel"))

                // The question may come up without a window, from the menu bar
                NSApp.activate(ignoringOtherApps: true)

                if alert.runModal() == .alertFirstButtonReturn {
                    self.disconnect(target, force: force)
                }
            }
        }
    }

    func disconnect(_ target: Target, force: Bool = false) {
        guard !busyTargets.contains(target.iqn) else { return }
        busyTargets.insert(target.iqn)

        Task {
            let code = await daemon.logout(target.iqn, force: force)
            busyTargets.remove(target.iqn)

            if code == EBUSY && !force {
                confirmForcedDisconnect(target)
            } else if code != 0 && code != ENOTCONN {
                report(String(localized: "Could not disconnect from “\(target.displayName)”"), code)
            }
            await refresh()
        }
    }

    /// Asks whether to disconnect even though volumes are in use.
    private func confirmForcedDisconnect(_ target: Target) {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = String(localized: "A volume of “\(target.displayName)” is in use")
        alert.informativeText = String(localized: "Quit the applications that use the volume and try again. If you disconnect regardless, data that has not been written yet will be lost.")
        alert.addButton(withTitle: String(localized: "Cancel"))
        alert.addButton(withTitle: String(localized: "Disconnect Anyway"))
        alert.buttons.last?.hasDestructiveAction = true

        // The question may come up without a window, from the menu bar
        NSApp.activate(ignoringOtherApps: true)

        if alert.runModal() == .alertSecondButtonReturn {
            disconnect(target, force: true)
        }
    }

    // MARK: Targets

    /// Adds a target with the given portals; returns whether it was added.
    func addTarget(_ iqn: String, portals: [String], chapName: String? = nil, chapSecret: String? = nil) async -> Bool {
        var added = false

        for portal in portals {
            let code = await daemon.addTarget(iqn, portal: portal)

            if code == 0 {
                added = true
            } else if code != EEXIST {
                report(String(localized: "Could not add the target"), code)
                return false
            }
        }

        if let chapName, !chapName.isEmpty {
            var settings: [String: Any] = ["InitiatorAuth": InitiatorAuth.chap.rawValue, "InitiatorCHAPName": chapName]
            if let chapSecret, !chapSecret.isEmpty { settings["InitiatorSecret"] = chapSecret }
            _ = await daemon.updateTarget(iqn, settings: settings)
        }

        await refresh()

        if added || target(iqn) != nil {
            selection = iqn
        }
        return true
    }

    func remove(_ target: Target) {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = String(localized: "Remove “\(target.displayName)”?")
        alert.informativeText = String(localized: "The target and its settings will be removed from this Mac. Data on the target is not affected.")
        alert.addButton(withTitle: String(localized: "Remove"))
        alert.addButton(withTitle: String(localized: "Cancel"))
        alert.buttons.first?.hasDestructiveAction = true

        guard alert.runModal() == .alertFirstButtonReturn else { return }

        Task {
            let code = await daemon.removeTarget(target.iqn)

            if code == EBUSY {
                error = OperationError(title: String(localized: "Could not remove the target"),
                                       message: String(localized: "Disconnect from the target first."))
            } else if code != 0 {
                report(String(localized: "Could not remove the target"), code)
            }
            await refresh()
        }
    }

    func update(_ target: Target, _ settings: [String: Any]) {
        Task {
            let code = await daemon.updateTarget(target.iqn, settings: settings)
            if code != 0 { report(String(localized: "Could not change the settings"), code) }
            await refresh()
        }
    }

    func discover(_ portal: String) async -> Result<[DiscoveredTarget], OperationError> {
        let result = await daemon.discover(portal)

        guard result.error == 0 else {
            report(String(localized: "Could not query “\(portal)”"), result.error, status: result.status)
            let failure = error ?? OperationError(title: "", message: "")
            error = nil
            return .failure(failure)
        }
        return .success(result.targets)
    }

    // MARK: Initiator and discovery

    func updateInitiator(_ settings: [String: Any]) {
        Task {
            let code = await daemon.updateInitiator(settings)
            if code != 0 { report(String(localized: "Could not change the settings"), code) }
            await refresh()
        }
    }

    func updateDiscovery(_ settings: [String: Any]) {
        Task {
            let code = await daemon.updateDiscovery(settings)
            if code != 0 { report(String(localized: "Could not change the settings"), code) }
            await refresh()
        }
    }

    func addDiscoveryPortal(_ portal: String) {
        Task {
            let code = await daemon.addDiscoveryPortal(portal)
            if code != 0 { report(String(localized: "Could not add the discovery portal"), code) }
            await refresh()
        }
    }

    func removeDiscoveryPortal(_ portal: Portal) {
        Task {
            let code = await daemon.removeDiscoveryPortal(portal.address)

            if code == EBUSY {
                error = OperationError(title: String(localized: "Could not remove the discovery portal"),
                                       message: String(localized: "Disconnect from the targets of the portal first."))
            } else if code != 0 {
                report(String(localized: "Could not remove the discovery portal"), code)
            }
            await refresh()
        }
    }

    // MARK: Disks

    func layout(of disk: Disk) -> DiskLayout? {
        guard let bsdName = disk.bsdName else { return nil }
        return layouts[bsdName]
    }

    func mount(_ volume: Volume) {
        Task {
            let result = await DiskUtility.mount(volume.bsdName)
            if result.status != 0 {
                error = OperationError(title: String(localized: "Could not mount the volume"),
                                       message: result.errorOutput.isEmpty ? String(data: result.output, encoding: .utf8) ?? "" : result.errorOutput)
            }
            await refresh()
        }
    }

    func unmount(_ volume: Volume) {
        Task {
            let result = await DiskUtility.unmount(volume.bsdName)
            if result.status != 0 {
                error = OperationError(title: String(localized: "Could not unmount the volume"),
                                       message: String(localized: "The volume is in use. Quit the applications that use it and try again."))
            }
            await refresh()
        }
    }

    func format(_ disk: Disk, of target: Target, as format: VolumeFormat, name: String) {
        guard let bsdName = disk.bsdName, !busyDisks.contains(bsdName) else { return }
        busyDisks.insert(bsdName)

        Task {
            // Make sure that the name still refers to the disk of the target
            // (and not to some other disk that has taken its place)
            await refresh()

            let current = self.target(target.iqn)?.disks.first { $0.lun == disk.lun }
            let verified = current?.bsdName == bsdName ? await DiskUtility.isDiskImage(bsdName, size: disk.size) : false

            guard verified else {
                busyDisks.remove(bsdName)
                error = OperationError(title: String(localized: "Could not format the disk"),
                                       message: String(localized: "The disk is no longer attached."))
                return
            }

            let result = await DiskUtility.erase(bsdName, format: format, name: name)
            busyDisks.remove(bsdName)

            if result.status != 0 {
                let output = String(data: result.output, encoding: .utf8) ?? ""
                error = OperationError(title: String(localized: "Could not format the disk"),
                                       message: result.errorOutput.isEmpty ? output : result.errorOutput)
            }
            await refresh()
        }
    }

    func reveal(_ volume: Volume) {
        guard let mountPoint = volume.mountPoint else { return }
        NSWorkspace.shared.open(URL(fileURLWithPath: mountPoint))
    }

    func openDiskUtility() {
        if let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "com.apple.DiskUtility") {
            NSWorkspace.shared.open(url)
        }
    }

    // MARK: Daemon

    func startDaemon() {
        daemon.launchDaemon = true
        Task { await refresh() }
    }

    func stopDaemon() {
        if connectedCount > 0 {
            let alert = NSAlert()
            alert.alertStyle = .warning
            alert.messageText = String(localized: "Stop the iSCSI daemon?")
            alert.informativeText = String(localized: "All targets will be disconnected.")
            alert.addButton(withTitle: String(localized: "Stop"))
            alert.addButton(withTitle: String(localized: "Cancel"))

            guard alert.runModal() == .alertFirstButtonReturn else { return }
        }

        Task {
            _ = await daemon.shutdown()
            try? await Task.sleep(nanoseconds: 1_500_000_000)
            await refresh()
        }
    }

    func showLog() {
        guard let path = DaemonClient.logPath else { return }

        if !FileManager.default.fileExists(atPath: path) {
            FileManager.default.createFile(atPath: path, contents: nil)
        }
        NSWorkspace.shared.open(URL(fileURLWithPath: path))
    }

    // MARK: Language

    /// The language that is set for the user interface.
    @Published private(set) var language = AppLanguage.selected

    func setLanguage(_ language: AppLanguage) {
        guard language != self.language else { return }

        AppLanguage.select(language)
        self.language = language

        guard language.needsRestart else { return }

        // The choice is made in a menu, which has to close first.  (The run
        // loop is asked rather than the main queue, which would be held up
        // for as long as the alert is open.)
        RunLoop.main.perform {
            MainActor.assumeIsolated {
                let alert = NSAlert()
                alert.messageText = String(localized: "Restart LunLink to change the language?")
                alert.informativeText = String(localized: "Targets stay connected while the application restarts.")
                alert.addButton(withTitle: String(localized: "Restart"))
                alert.addButton(withTitle: String(localized: "Later"))

                if alert.runModal() == .alertFirstButtonReturn {
                    AppLanguage.relaunch()
                }
            }
        }
    }

    /// Whether the daemon starts when the user logs in.
    var startsAtLogin: Bool { LoginAgent.isInstalled }

    func setStartsAtLogin(_ enable: Bool) {
        // launchd takes over the socket of the daemon, so the daemon that
        // is running has to make way first
        if connectedCount > 0 {
            error = OperationError(title: String(localized: "Could not change the setting"),
                                   message: String(localized: "Disconnect from all targets first: the iSCSI daemon has to be restarted."))
            return
        }

        Task {
            _ = await daemon.shutdown()
            try? await Task.sleep(nanoseconds: 1_000_000_000)

            let failure = enable ? await LoginAgent.install() : await LoginAgent.uninstall()

            if let failure {
                error = OperationError(title: String(localized: "Could not change the setting"), message: failure)
            }

            daemon.launchDaemon = true
            objectWillChange.send()
            await refresh()
        }
    }
}
