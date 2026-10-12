// Copyright (c) 2026, LunLink contributors
// SPDX-License-Identifier: BSD-2-Clause

import Foundation

/// Talks to the iSCSI daemon on behalf of the application.
///
/// Requests are blocking (logging in to a target may take many seconds),
/// hence they are made off the main thread.  The state of the initiator is
/// polled over a connection that is kept open, while every other operation
/// uses a connection of its own so that the two never hold each other up.
final class DaemonClient: @unchecked Sendable {
    static let shared = DaemonClient()

    /// The daemon that ships inside the application bundle.
    static var daemonPath: String {
        Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS/iscsid").path
    }

    private let pollQueue = DispatchQueue(label: "iscsi.poll")
    private let operationQueue = DispatchQueue(label: "iscsi.operation", attributes: .concurrent)
    private var pollHandle: Int32 = -1

    /// Whether to start the daemon if it is found not to be running.
    private let lock = NSLock()
    private var _launchDaemon = true
    var launchDaemon: Bool {
        get { lock.lock(); defer { lock.unlock() }; return _launchDaemon }
        set { lock.lock(); _launchDaemon = newValue; lock.unlock() }
    }

    private func connect() -> Int32 {
        if launchDaemon {
            return DaemonClient.daemonPath.withCString { iSCSIDaemonConnectOrLaunch($0) }
        }
        return iSCSIDaemonConnect()
    }

    /// Carries out an operation over a connection of its own.
    private func perform<T: Sendable>(_ body: @escaping @Sendable (Int32) -> T) async -> T {
        await withCheckedContinuation { continuation in
            operationQueue.async {
                let handle = self.connect()
                let result = body(handle)
                iSCSIDaemonDisconnect(handle)
                continuation.resume(returning: result)
            }
        }
    }

    // MARK: State

    func snapshot() async -> Snapshot {
        await withCheckedContinuation { continuation in
            pollQueue.async {
                if self.pollHandle < 0 {
                    self.pollHandle = self.connect()
                }

                var snapshot = Snapshot((iSCSIAppCopySnapshot(self.pollHandle) as? [String: Any]) ?? [:])

                // The daemon went away: try once more over a new connection
                if !snapshot.daemonRunning && self.pollHandle >= 0 {
                    iSCSIDaemonDisconnect(self.pollHandle)
                    self.pollHandle = self.connect()
                    snapshot = Snapshot((iSCSIAppCopySnapshot(self.pollHandle) as? [String: Any]) ?? [:])
                }

                if !snapshot.daemonRunning && self.pollHandle >= 0 {
                    iSCSIDaemonDisconnect(self.pollHandle)
                    self.pollHandle = -1
                }
                continuation.resume(returning: snapshot)
            }
        }
    }

    // MARK: Sessions

    /// Logs in to a target; returns an error code and the iSCSI login status.
    func login(_ iqn: String) async -> (error: Int32, status: Int32) {
        await perform { handle in
            var status: Int32 = 0
            let error = iSCSIAppLogin(handle, iqn as CFString, &status)
            return (error, status)
        }
    }

    func logout(_ iqn: String, force: Bool) async -> Int32 {
        await perform { iSCSIAppLogout($0, iqn as CFString, force) }
    }

    // MARK: Targets

    func addTarget(_ iqn: String, portal: String) async -> Int32 {
        await perform { iSCSIAppAddTarget($0, iqn as CFString, portal as CFString) }
    }

    func removeTarget(_ iqn: String) async -> Int32 {
        await perform { iSCSIAppRemoveTarget($0, iqn as CFString) }
    }

    func updateTarget(_ iqn: String, settings: [String: Any]) async -> Int32 {
        let settings = Settings(settings)
        return await perform { iSCSIAppUpdateTarget($0, iqn as CFString, settings.dictionary) }
    }

    /// Queries a portal for its targets.
    func discover(_ portal: String) async -> (targets: [DiscoveredTarget], error: Int32, status: Int32) {
        await perform { handle in
            var error: Int32 = 0
            var status: Int32 = 0
            let result = iSCSIAppCopyDiscoveredTargets(handle, portal as CFString, &error, &status)
            let targets = ((result as? [[String: Any]]) ?? []).compactMap(DiscoveredTarget.init)
            return (targets, error, status)
        }
    }

    // MARK: Initiator and discovery

    func updateInitiator(_ settings: [String: Any]) async -> Int32 {
        let settings = Settings(settings)
        return await perform { iSCSIAppUpdateInitiator($0, settings.dictionary) }
    }

    func updateDiscovery(_ settings: [String: Any]) async -> Int32 {
        let settings = Settings(settings)
        return await perform { iSCSIAppUpdateDiscovery($0, settings.dictionary) }
    }

    func addDiscoveryPortal(_ portal: String) async -> Int32 {
        await perform { iSCSIAppAddDiscoveryPortal($0, portal as CFString) }
    }

    func removeDiscoveryPortal(_ address: String) async -> Int32 {
        await perform { iSCSIAppRemoveDiscoveryPortal($0, address as CFString) }
    }

    // MARK: Daemon

    /// Asks the daemon to log out of all targets and to exit.
    func shutdown() async -> Int32 {
        launchDaemon = false

        return await withCheckedContinuation { continuation in
            operationQueue.async {
                let handle = iSCSIDaemonConnect()
                let error = handle >= 0 ? iSCSIDaemonShutdown(handle) : 0
                iSCSIDaemonDisconnect(handle)
                continuation.resume(returning: error)
            }
        }
    }

    static var logPath: String? { iSCSIAppCopyDaemonLogPath() as String? }
    static var socketPath: String? { iSCSIAppCopyDaemonSocketPath() as String? }

    static func loginStatusDescription(_ status: Int32) -> String {
        (iSCSIAppCopyLoginStatusDescription(status) as String?) ?? ""
    }
}

/// Settings on their way to the daemon.  The dictionary is immutable, which
/// makes it safe to hand to another thread.
private struct Settings: @unchecked Sendable {
    let dictionary: NSDictionary

    init(_ settings: [String: Any]) {
        dictionary = settings as NSDictionary
    }
}

/// Runs a command-line tool and collects its output.
enum Tool {
    struct Result: Sendable {
        var status: Int32
        var output: Data
        var errorOutput: String
    }

    static func run(_ path: String, _ arguments: [String]) async -> Result {
        await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                let process = Process()
                let output = Pipe()
                let errorOutput = Pipe()

                process.executableURL = URL(fileURLWithPath: path)
                process.arguments = arguments
                process.standardInput = FileHandle.nullDevice
                process.standardOutput = output
                process.standardError = errorOutput

                do {
                    try process.run()
                } catch {
                    continuation.resume(returning: Result(status: -1, output: Data(),
                                                          errorOutput: error.localizedDescription))
                    return
                }

                // The pipes are drained before waiting so that a tool with
                // plenty of output cannot stall
                let data = output.fileHandleForReading.readDataToEndOfFile()
                let errorData = errorOutput.fileHandleForReading.readDataToEndOfFile()
                process.waitUntilExit()

                continuation.resume(returning: Result(status: process.terminationStatus, output: data,
                                                      errorOutput: String(data: errorData, encoding: .utf8) ?? ""))
            }
        }
    }
}

/// Finds out about the partitions and volumes of disks, and formats disks.
enum DiskUtility {
    static let path = "/usr/sbin/diskutil"

    /// Determines the layout of the specified whole disks.
    static func layouts(of disks: Set<String>) async -> [String: DiskLayout] {
        guard !disks.isEmpty else { return [:] }

        let result = await Tool.run(path, ["list", "-plist"])

        guard result.status == 0,
              let plist = try? PropertyListSerialization.propertyList(from: result.output, format: nil),
              let entries = (plist as? [String: Any])?["AllDisksAndPartitions"] as? [[String: Any]]
        else { return [:] }

        func volume(_ dictionary: [String: Any]) -> Volume? {
            guard let bsdName = dictionary["DeviceIdentifier"] as? String else { return nil }
            return Volume(bsdName: bsdName,
                          name: dictionary["VolumeName"] as? String ?? "",
                          mountPoint: dictionary["MountPoint"] as? String,
                          size: (dictionary["Size"] as? NSNumber)?.int64Value ?? 0,
                          content: dictionary["Content"] as? String ?? "")
        }

        // APFS volumes live in containers, which appear as disks of their
        // own that refer to the partitions that back them
        var containerVolumes: [String: [Volume]] = [:]

        for entry in entries {
            guard let stores = entry["APFSPhysicalStores"] as? [[String: Any]] else { continue }
            let volumes = (entry["APFSVolumes"] as? [[String: Any]] ?? []).compactMap(volume)

            for store in stores {
                if let identifier = store["DeviceIdentifier"] as? String {
                    containerVolumes[identifier, default: []] += volumes
                }
            }
        }

        var layouts: [String: DiskLayout] = [:]

        for entry in entries {
            guard let identifier = entry["DeviceIdentifier"] as? String, disks.contains(identifier) else { continue }

            let partitions = entry["Partitions"] as? [[String: Any]] ?? []
            var volumes: [Volume] = []

            for partition in partitions {
                guard let item = volume(partition) else { continue }

                if let contained = containerVolumes[item.bsdName] {
                    volumes += contained
                }
                // Partitions that hold no file system of interest are skipped
                else if item.content != "EFI" && item.content != "Apple_APFS" {
                    volumes.append(item)
                }
            }

            // A disk may also carry a file system without a partition map
            let content = entry["Content"] as? String ?? ""

            if partitions.isEmpty, let item = volume(entry), item.mountPoint != nil || !item.name.isEmpty {
                volumes.append(item)
            }

            layouts[identifier] = DiskLayout(initialized: !partitions.isEmpty || !content.isEmpty, volumes: volumes)
        }
        return layouts
    }

    static func mount(_ bsdName: String) async -> Tool.Result {
        await Tool.run(path, ["mount", bsdName])
    }

    static func unmount(_ bsdName: String) async -> Tool.Result {
        await Tool.run(path, ["unmount", bsdName])
    }

    /// Confirms that a disk is a whole disk that is backed by a disk image
    /// and has the expected size.  The name of a disk says little about
    /// its identity (names are reused once a disk is gone), so this is
    /// checked right before a disk is erased.
    static func isDiskImage(_ bsdName: String, size: Int64) async -> Bool {
        let result = await Tool.run(path, ["info", "-plist", "/dev/" + bsdName])

        guard result.status == 0,
              let plist = try? PropertyListSerialization.propertyList(from: result.output, format: nil),
              let info = plist as? [String: Any] else { return false }

        let total = (info["TotalSize"] as? NSNumber ?? info["Size"] as? NSNumber)?.int64Value

        return info["BusProtocol"] as? String == "Disk Image" && info["WholeDisk"] as? Bool == true && total == size
    }

    /// Erases a disk and creates a single volume on it.
    static func erase(_ bsdName: String, format: VolumeFormat, name: String) async -> Tool.Result {
        await Tool.run(path, ["eraseDisk", format.rawValue, name, "GPT", "/dev/" + bsdName])
    }
}

/// The file systems that a disk can be formatted with.
enum VolumeFormat: String, CaseIterable, Identifiable {
    case apfs = "APFS"
    case hfs = "JHFS+"
    case exfat = "ExFAT"

    var id: String { rawValue }

    var title: String {
        switch self {
        case .apfs: return "APFS"
        case .hfs: return String(localized: "Mac OS Extended (Journaled)")
        case .exfat: return "ExFAT"
        }
    }
}

/// Manages the launch agent that starts the daemon when the user logs in.
enum LoginAgent {
    /// The daemon that the installed launch agent starts, if any.
    static var installedDaemonPath: String? {
        iSCSILaunchAgentCopyDaemonPath() as String?
    }

    static var isInstalled: Bool { installedDaemonPath != nil }

    /// Installs the launch agent and starts the daemon through it. No daemon
    /// must be running, since launchd takes over the socket of the daemon.
    static func install() async -> String? {
        await run { DaemonClient.daemonPath.withCString { iSCSILaunchAgentInstall($0) } }
    }

    /// Removes the launch agent (which stops the daemon it started).
    static func uninstall() async -> String? {
        await run { iSCSILaunchAgentRemove() }
    }

    /// Runs an operation off the main thread; returns a description of the
    /// error if it failed.
    private static func run(_ operation: @escaping @Sendable () -> Int32) async -> String? {
        await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                let code = operation()
                continuation.resume(returning: code == 0 ? nil : String(cString: strerror(code)))
            }
        }
    }
}
