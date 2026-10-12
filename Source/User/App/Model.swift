// Copyright (c) 2026, LunLink contributors
// SPDX-License-Identifier: BSD-2-Clause

import Foundation

/// A portal (network address) of a target.
struct Portal: Identifiable, Hashable {
    var address: String
    var port: String
    var interface: String
    var active: Bool

    var id: String { address + ":" + port }

    /// The portal in the form that the daemon parses ("address:port").
    var endpoint: String {
        address.contains(":") ? "[\(address)]:\(port)" : "\(address):\(port)"
    }

    init(address: String, port: String = "3260", interface: String = "default", active: Bool = false) {
        self.address = address
        self.port = port
        self.interface = interface
        self.active = active
    }

    init?(_ dictionary: [String: Any]) {
        guard let address = dictionary["Address"] as? String else { return nil }
        self.address = address
        port = dictionary["Port"] as? String ?? "3260"
        interface = dictionary["Interface"] as? String ?? "default"
        active = dictionary["Active"] as? Bool ?? false
    }
}

/// A logical unit of a target that is logged in.
struct Disk: Identifiable, Hashable {
    var lun: Int
    var vendor: String
    var product: String
    var serialNumber: String
    var blockSize: Int
    var blockCount: Int64
    var readOnly: Bool

    /// The BSD name of the disk (e.g. "disk4") if it is attached.
    var bsdName: String?

    /// Why the logical unit could not be attached, if it could not.
    var error: String?

    var id: Int { lun }
    var size: Int64 { blockCount * Int64(blockSize) }

    var model: String {
        [vendor, product].filter { !$0.isEmpty }.joined(separator: " ")
    }

    /// The error in the language of the user interface.  The daemon may
    /// append a detail to its message, after a colon.
    var localizedError: String? {
        guard let error else { return nil }

        let parts = error.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
        guard let message = parts.first else { return nil }

        return parts.count > 1 ? "\(translated(message)) (\(parts[1]))" : translated(message)
    }

    init?(_ dictionary: [String: Any]) {
        guard let lun = dictionary["LUN"] as? Int else { return nil }
        self.lun = lun
        vendor = dictionary["Vendor"] as? String ?? ""
        product = dictionary["Product"] as? String ?? ""
        serialNumber = dictionary["Serial Number"] as? String ?? ""
        blockSize = dictionary["Block Size"] as? Int ?? 512
        blockCount = (dictionary["Block Count"] as? NSNumber)?.int64Value ?? 0
        readOnly = dictionary["Read Only"] as? Bool ?? false
        bsdName = dictionary["BSD Name"] as? String
        error = dictionary["Error"] as? String
    }
}

/// How the initiator proves its identity to a target.
enum InitiatorAuth: String, CaseIterable, Identifiable {
    /// Use the credentials that are configured for the initiator in general.
    case inherit = "Default"
    case none = "None"
    case chap = "CHAP"

    var id: String { rawValue }
}

/// The session of a target that is logged in.
struct Session: Hashable {
    var recovering: Bool
    var parameters: [SessionParameter]
}

struct SessionParameter: Identifiable, Hashable {
    var name: String
    var value: String
    var id: String { name }
}

struct Target: Identifiable, Hashable {
    var iqn: String
    var alias: String
    var dynamic: Bool
    var discoveryPortal: String?
    var autoLogin: Bool
    var persistent: Bool
    var readOnly: Bool
    var headerDigest: Bool
    var dataDigest: Bool
    var initiatorAuth: InitiatorAuth
    var initiatorCHAPName: String
    var hasInitiatorSecret: Bool
    var mutualCHAP: Bool
    var targetCHAPName: String
    var hasTargetSecret: Bool
    var portals: [Portal]
    var session: Session?
    var disks: [Disk]

    var id: String { iqn }
    var connected: Bool { session != nil }

    /// A name for display: the part of the name that tells the targets of a
    /// server apart.  (The alias is of little use for this purpose: many
    /// servers give all of their targets the same one.)
    var displayName: String {
        if let colon = iqn.firstIndex(of: ":") {
            let suffix = iqn[iqn.index(after: colon)...]
            if !suffix.isEmpty { return String(suffix) }
        }
        return iqn
    }

    init?(_ dictionary: [String: Any]) {
        guard let iqn = dictionary["IQN"] as? String else { return nil }
        self.iqn = iqn
        alias = dictionary["Alias"] as? String ?? ""
        dynamic = dictionary["Dynamic"] as? Bool ?? false
        discoveryPortal = dictionary["DiscoveryPortal"] as? String
        autoLogin = dictionary["AutoLogin"] as? Bool ?? false
        persistent = dictionary["Persistent"] as? Bool ?? false
        readOnly = dictionary["ReadOnly"] as? Bool ?? false
        headerDigest = dictionary["HeaderDigest"] as? Bool ?? false
        dataDigest = dictionary["DataDigest"] as? Bool ?? false
        initiatorAuth = InitiatorAuth(rawValue: dictionary["InitiatorAuth"] as? String ?? "") ?? .inherit
        initiatorCHAPName = dictionary["InitiatorCHAPName"] as? String ?? ""
        hasInitiatorSecret = dictionary["HasInitiatorSecret"] as? Bool ?? false
        mutualCHAP = dictionary["MutualCHAP"] as? Bool ?? false
        targetCHAPName = dictionary["TargetCHAPName"] as? String ?? ""
        hasTargetSecret = dictionary["HasTargetSecret"] as? Bool ?? false
        portals = (dictionary["Portals"] as? [[String: Any]] ?? []).compactMap(Portal.init)
        disks = (dictionary["Disks"] as? [[String: Any]] ?? []).compactMap(Disk.init)

        if let properties = dictionary["Session"] as? [String: Any] {
            // The order in which the negotiated parameters are shown
            let names = ["InitialR2T", "ImmediateData", "MaxBurstLength", "FirstBurstLength",
                         "MaxOutstandingR2T", "DefaultTime2Wait", "DefaultTime2Retain",
                         "ErrorRecoveryLevel", "TargetPortalGroupTag"]
            let parameters = names.compactMap { name -> SessionParameter? in
                guard let value = properties[name] else { return nil }
                return SessionParameter(name: name, value: "\(value)")
            }
            session = Session(recovering: properties["State"] as? String == "Recovering", parameters: parameters)
        }
    }
}

struct Initiator: Hashable {
    var name = ""
    var alias = ""
    var chap = false
    var chapName = ""
    var hasSecret = false

    init() {}

    init(_ dictionary: [String: Any]) {
        name = dictionary["Name"] as? String ?? ""
        alias = dictionary["Alias"] as? String ?? ""
        chap = dictionary["CHAP"] as? Bool ?? false
        chapName = dictionary["CHAPName"] as? String ?? ""
        hasSecret = dictionary["HasSecret"] as? Bool ?? false
    }
}

struct Discovery: Hashable {
    var enabled = false
    var interval = 300
    var portals: [Portal] = []

    init() {}

    init(_ dictionary: [String: Any]) {
        enabled = dictionary["Enabled"] as? Bool ?? false
        interval = dictionary["Interval"] as? Int ?? 300
        portals = (dictionary["Portals"] as? [[String: Any]] ?? []).compactMap(Portal.init)
    }
}

/// The configuration and state of the initiator at a point in time.
struct Snapshot: Hashable {
    var daemonRunning = false
    var daemonVersion = ""
    var initiator = Initiator()
    var discovery = Discovery()
    var targets: [Target] = []

    init() {}

    init(_ dictionary: [String: Any]) {
        let daemon = dictionary["Daemon"] as? [String: Any] ?? [:]
        daemonRunning = daemon["Running"] as? Bool ?? false
        daemonVersion = daemon["Version"] as? String ?? ""
        initiator = Initiator(dictionary["Initiator"] as? [String: Any] ?? [:])
        discovery = Discovery(dictionary["Discovery"] as? [String: Any] ?? [:])
        targets = (dictionary["Targets"] as? [[String: Any]] ?? []).compactMap(Target.init)
            .sorted { $0.iqn.localizedStandardCompare($1.iqn) == .orderedAscending }
    }
}

/// A target that a portal offers, as found by discovery.
struct DiscoveredTarget: Identifiable, Hashable {
    var iqn: String
    var portals: [Portal]
    var id: String { iqn }

    init?(_ dictionary: [String: Any]) {
        guard let iqn = dictionary["IQN"] as? String else { return nil }
        self.iqn = iqn
        portals = (dictionary["Portals"] as? [[String: Any]] ?? []).compactMap(Portal.init)
    }
}

/// A volume on a disk.
struct Volume: Identifiable, Hashable {
    /// The BSD name of the volume (e.g. "disk5s1").
    var bsdName: String
    var name: String
    var mountPoint: String?
    var size: Int64
    var content: String

    var id: String { bsdName }
}

/// What is known about the partitions and volumes of a disk.
struct DiskLayout: Hashable {
    /// The disk has a partition map or a file system.
    var initialized: Bool
    var volumes: [Volume]
}

/// An error of an operation, in a form fit for presentation.
struct OperationError: Error, Identifiable {
    var title: String
    var message: String
    let id = UUID()
}

extension Int64 {
    /// A size in bytes for display (decimal units, as the Finder shows them).
    var formattedSize: String {
        ByteCountFormatter.string(fromByteCount: self, countStyle: .file)
    }
}
