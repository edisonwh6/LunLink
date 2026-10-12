// Copyright (c) 2026, LunLink contributors
// SPDX-License-Identifier: BSD-2-Clause

import SwiftUI

/// The settings window.
struct SettingsView: View {
    var body: some View {
        TabView {
            GeneralSettings()
                .tabItem { Label("General", systemImage: "gearshape") }

            AuthenticationSettings()
                .tabItem { Label("Authentication", systemImage: "key") }

            DiscoverySettings()
                .tabItem { Label("Discovery", systemImage: "magnifyingglass") }
        }
        .frame(width: 520)
    }
}

/// The identity of the initiator and the daemon.
private struct GeneralSettings: View {
    @EnvironmentObject private var state: AppState
    @AppStorage(MenuBarItem.key) private var showMenuBarItem = true

    @StateObject private var name = Box("")
    @StateObject private var alias = Box("")

    var body: some View {
        Form {
            Section {
                TextField("Initiator name", text: $name.value)
                    .onSubmit(save)
                TextField("Alias", text: $alias.value)
                    .onSubmit(save)

                HStack {
                    Spacer()
                    Button("Save", action: save)
                        .disabled(!changed || state.connectedCount > 0)
                }
            } header: {
                Text("This Mac")
            } footer: {
                Text("Servers know this Mac by its initiator name, and may grant access to targets by it. The name can only be changed while no target is connected.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }

            Section("Daemon") {
                LabeledContent("Status") {
                    HStack(spacing: 8) {
                        if state.snapshot.daemonRunning {
                            Text("Running (version \(state.snapshot.daemonVersion))")
                            Button("Stop") { state.stopDaemon() }
                                .controlSize(.small)
                        } else {
                            Text("Not running")
                            Button("Start") { state.startDaemon() }
                                .controlSize(.small)
                        }
                    }
                    .fixedSize()
                }

                Toggle("Start the daemon when I log in", isOn: startsAtLogin)

                LabeledContent("Log") {
                    Button("Show Log") { state.showLog() }
                        .controlSize(.small)
                }
            }

            Section {
                Toggle("Show in the menu bar", isOn: $showMenuBarItem)
            } footer: {
                Text("While it is in the menu bar, the application keeps running there when its window is closed, and leaves the Dock. To quit it, click the item in the menu bar and choose Quit.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }

            Section {
                // Languages go by their own names
                Picker("Language", selection: language) {
                    Text("System Default").tag(AppLanguage.system)
                    Text(verbatim: "English").tag(AppLanguage.english)
                    Text(verbatim: "简体中文").tag(AppLanguage.chinese)
                }

                if state.language.needsRestart {
                    HStack {
                        Text("The language changes when the application is restarted.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Spacer()
                        Button("Restart Now") { AppLanguage.relaunch() }
                            .controlSize(.small)
                    }
                }
            }
        }
        .formStyle(.grouped)
        .fixedSize(horizontal: false, vertical: true)
        .onAppear(perform: load)
        .onChange(of: state.snapshot.initiator) { _ in load() }
    }

    private func load() {
        name.value = state.snapshot.initiator.name
        alias.value = state.snapshot.initiator.alias
    }

    private var changed: Bool {
        name.value != state.snapshot.initiator.name || alias.value != state.snapshot.initiator.alias
    }

    private func save() {
        guard changed, state.connectedCount == 0 else { return }
        state.updateInitiator(["Name": name.value.trimmingCharacters(in: .whitespaces),
                               "Alias": alias.value.trimmingCharacters(in: .whitespaces)])
    }

    private var startsAtLogin: Binding<Bool> {
        Binding(get: { state.startsAtLogin },
                set: { state.setStartsAtLogin($0) })
    }

    private var language: Binding<AppLanguage> {
        Binding(get: { state.language },
                set: { state.setLanguage($0) })
    }
}

/// The credentials that the initiator presents unless a target has its own.
private struct AuthenticationSettings: View {
    @EnvironmentObject private var state: AppState

    @StateObject private var name = Box("")
    @StateObject private var secret = Box("")

    var body: some View {
        Form {
            Section {
                Toggle("Use CHAP", isOn: enabled)

                if state.snapshot.initiator.chap {
                    TextField("User name", text: $name.value)
                        .onSubmit(save)

                    SecureField("Password", text: $secret.value,
                                prompt: Text(state.snapshot.initiator.hasSecret ? "Saved in keychain" : "Required"))
                        .onSubmit(save)

                    HStack {
                        Spacer()
                        Button("Save", action: save)
                            .disabled(name.value == state.snapshot.initiator.chapName && secret.value.isEmpty)
                    }
                }
            } header: {
                Text("Default Credentials")
            } footer: {
                Text("These credentials are used for discovery, and for targets that have no credentials of their own.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .formStyle(.grouped)
        .fixedSize(horizontal: false, vertical: true)
        .onAppear { name.value = state.snapshot.initiator.chapName }
        .onChange(of: state.snapshot.initiator.chapName) { name.value = $0 }
    }

    private var enabled: Binding<Bool> {
        Binding(get: { state.snapshot.initiator.chap },
                set: { state.updateInitiator(["CHAP": $0]) })
    }

    private func save() {
        var settings: [String: Any] = ["CHAPName": name.value]
        if !secret.value.isEmpty { settings["Secret"] = secret.value }
        state.updateInitiator(settings)
        secret.value = ""
    }
}

/// Servers that are asked for their targets time and again.
private struct DiscoverySettings: View {
    @EnvironmentObject private var state: AppState

    @StateObject private var newPortal = Box("")

    var body: some View {
        Form {
            Section {
                Toggle("Look for new targets periodically", isOn: enabled)

                if state.snapshot.discovery.enabled {
                    Picker("Every", selection: interval) {
                        Text("minute").tag(60)
                        Text("5 minutes").tag(300)
                        Text("15 minutes").tag(900)
                        Text("hour").tag(3600)
                    }
                }
            } footer: {
                Text("Targets that a server offers are added automatically, and are removed when the server no longer offers them.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }

            Section("Servers") {
                ForEach(state.snapshot.discovery.portals) { portal in
                    LabeledContent {
                        Button {
                            state.removeDiscoveryPortal(portal)
                        } label: {
                            Image(systemName: "minus.circle")
                        }
                        .buttonStyle(.borderless)
                        .help("Remove")
                    } label: {
                        Text(verbatim: portal.port == "3260" ? portal.address : portal.endpoint)
                    }
                }

                HStack {
                    TextField("Address", text: $newPortal.value, prompt: Text(verbatim: "192.168.1.10"))
                        .labelsHidden()
                        .onSubmit(add)

                    Button("Add", action: add)
                        .disabled(newPortal.value.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            }
        }
        .formStyle(.grouped)
        .fixedSize(horizontal: false, vertical: true)
    }

    private var enabled: Binding<Bool> {
        Binding(get: { state.snapshot.discovery.enabled },
                set: { state.updateDiscovery(["Enabled": $0]) })
    }

    private var interval: Binding<Int> {
        Binding(get: {
                    // Snap to the nearest of the intervals on offer
                    let choices = [60, 300, 900, 3600]
                    let current = state.snapshot.discovery.interval
                    return choices.min { abs($0 - current) < abs($1 - current) } ?? 300
                },
                set: { state.updateDiscovery(["Interval": $0]) })
    }

    private func add() {
        let portal = newPortal.value.trimmingCharacters(in: .whitespaces)
        guard !portal.isEmpty else { return }

        state.addDiscoveryPortal(portal)
        newPortal.value = ""
    }
}
