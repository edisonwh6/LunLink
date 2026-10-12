// Copyright (c) 2026, LunLink contributors
// SPDX-License-Identifier: BSD-2-Clause

import AppKit

/// The language of the user interface.
///
/// The choice is kept where the system keeps the language of an application
/// (System Settings → Language & Region → Applications), so that the two
/// agree.  It takes effect when the application starts: menus, alerts and
/// formatters all settle on a language at launch.
enum AppLanguage: String, CaseIterable, Identifiable {
    /// Whichever of the languages below the system prefers.
    case system = ""
    case english = "en"
    case chinese = "zh-Hans"

    var id: String { rawValue }

    private static let key = "AppleLanguages"

    /// The language that is set for the application.
    static var selected: AppLanguage {
        guard let identifier = Bundle.main.bundleIdentifier,
              let languages = UserDefaults.standard.persistentDomain(forName: identifier)?[key] as? [String],
              let first = languages.first else { return .system }

        if first.hasPrefix("zh") { return .chinese }
        if first.hasPrefix("en") { return .english }
        return .system
    }

    static func select(_ language: AppLanguage) {
        if language == .system {
            UserDefaults.standard.removeObject(forKey: key)
        } else {
            UserDefaults.standard.set([language.rawValue], forKey: key)
        }
    }

    /// The localization of the application that the choice amounts to.
    private var localization: String {
        var preferences = [rawValue]

        if self == .system {
            preferences = UserDefaults.standard.persistentDomain(forName: UserDefaults.globalDomain)?[Self.key] as? [String] ?? []
        }
        return Bundle.preferredLocalizations(from: Bundle.main.localizations, forPreferences: preferences).first ?? "en"
    }

    /// Whether the user interface is shown in another language than this
    /// one, that is, whether the application has to restart to adopt it.
    var needsRestart: Bool {
        localization != Bundle.main.preferredLocalizations.first
    }

    /// Starts the application anew and quits this instance of it.  Sessions
    /// are not affected: they belong to the daemon.
    @MainActor
    static func relaunch() {
        UserDefaults.standard.synchronize()

        let configuration = NSWorkspace.OpenConfiguration()
        configuration.createsNewApplicationInstance = true

        // An application that was pointed at an environment of its own
        // (see iscsid(8)) stays there
        configuration.environment = ProcessInfo.processInfo.environment.filter { $0.key.hasPrefix("ISCSI_") }

        NSWorkspace.shared.openApplication(at: Bundle.main.bundleURL, configuration: configuration) { application, _ in
            guard application != nil else { return }
            DispatchQueue.main.async { NSApp.terminate(nil) }
        }
    }
}

/// Translates a message of the daemon or of the client library, both of
/// which speak English only.  Messages that are not known are left as is.
func translated(_ message: String) -> String {
    Bundle.main.localizedString(forKey: message, value: message, table: "Daemon")
}
