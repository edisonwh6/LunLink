// Copyright (c) 2026, LunLink contributors
// SPDX-License-Identifier: BSD-2-Clause

import SwiftUI

/// Everything about a target: its state, disks, portals and settings.
struct TargetDetailView: View {
    @EnvironmentObject private var state: AppState
    let target: Target

    var body: some View {
        Form {
            Section {
                header
            }

            if target.connected {
                Section("Disks") {
                    if target.disks.isEmpty {
                        Text("The target offers no disks.")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(target.disks) { disk in
                        DiskView(target: target, disk: disk)
                    }
                }
            }

            Section("Server") {
                ForEach(target.portals) { portal in
                    LabeledContent {
                        if portal.active {
                            Text("In use")
                                .foregroundStyle(.secondary)
                        }
                    } label: {
                        Text(verbatim: portal.port == "3260" ? portal.address : portal.endpoint)
                            .textSelection(.enabled)
                    }
                }

                if target.dynamic, let discoveryPortal = target.discoveryPortal {
                    LabeledContent("Discovered through", value: discoveryPortal)
                }
            }

            Section {
                Toggle("Connect automatically", isOn: setting(\.autoLogin, "AutoLogin"))
                Toggle("Attach disks read-only", isOn: setting(\.readOnly, "ReadOnly"))
                    .disabled(target.connected)
                Toggle("Flush after every write", isOn: setting(\.syncWrites, "SyncWrites"))
                    .disabled(target.connected)
                Toggle("Verify headers (CRC32C)", isOn: setting(\.headerDigest, "HeaderDigest"))
                    .disabled(target.connected)
                Toggle("Verify data (CRC32C)", isOn: setting(\.dataDigest, "DataDigest"))
                    .disabled(target.connected)
            } header: {
                Text("Options")
            } footer: {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Writes are normally confirmed at once and stored by the server a moment later, which is fast. Flushing after every write is much slower, and only matters if the server loses power or the daemon is cut short.")

                    if target.connected {
                        Text("Some options can only be changed while the target is disconnected.")
                    }
                }
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
            }

            AuthenticationSection(target: target)

            if let session = target.session {
                Section("Session") {
                    ForEach(session.parameters) { parameter in
                        LabeledContent(parameter.name, value: parameter.value)
                    }
                }
            }
        }
        .formStyle(.grouped)
    }

    // MARK: Header

    private var busy: Bool { state.busyTargets.contains(target.iqn) }

    private var header: some View {
        HStack(alignment: .center, spacing: 14) {
            Image(systemName: target.connected ? "externaldrive.fill.badge.checkmark" : "externaldrive")
                .font(.system(size: 34))
                .foregroundStyle(target.connected ? Color.accentColor : Color.secondary)
                .frame(width: 48)

            VStack(alignment: .leading, spacing: 3) {
                Text(target.displayName)
                    .font(.title3.weight(.semibold))
                    .lineLimit(1)
                    .truncationMode(.middle)

                Text(verbatim: target.alias.isEmpty ? target.iqn : "\(target.iqn) · \(target.alias)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .lineLimit(2)

                HStack(spacing: 5) {
                    StatusDot(target: target)
                    Text(statusText)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                .padding(.top, 2)
            }

            Spacer()

            if busy {
                ProgressView()
                    .controlSize(.small)
            }

            if target.connected {
                Button("Disconnect") { state.confirmDisconnect(target) }
                    .controlSize(.large)
                    .disabled(busy)
            } else {
                Button("Connect") { state.connect(target) }
                    .controlSize(.large)
                    .buttonStyle(.borderedProminent)
                    .disabled(busy)
            }

            Menu {
                if target.connected {
                    Button("Disconnect Anyway…") { state.confirmDisconnect(target, force: true) }
                }
                Button("Copy Name") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(target.iqn, forType: .string)
                }
                Divider()
                Button("Remove Target…") { state.remove(target) }
                    .disabled(target.connected)
            } label: {
                Image(systemName: "ellipsis.circle")
            }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .fixedSize()
            .help("More actions")
        }
        .padding(.vertical, 4)
    }

    private var statusText: String {
        if busy {
            return target.connected ? String(localized: "Disconnecting…") : String(localized: "Connecting…")
        }
        guard let session = target.session else { return String(localized: "Not connected") }
        return session.recovering ? String(localized: "Connection lost — reconnecting…") : String(localized: "Connected")
    }

    /// A binding to a setting of the target that is stored when changed.
    private func setting(_ keyPath: KeyPath<Target, Bool>, _ key: String) -> Binding<Bool> {
        Binding(get: { target[keyPath: keyPath] },
                set: { state.update(target, [key: $0]) })
    }
}

/// A disk of a target along with its volumes.
struct DiskView: View {
    @EnvironmentObject private var state: AppState
    let target: Target
    let disk: Disk
    @StateObject private var showingFormat = Box(false)

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 10) {
                Image(systemName: "internaldrive")
                    .font(.title2)
                    .foregroundStyle(.secondary)
                    .frame(width: 28)

                VStack(alignment: .leading, spacing: 1) {
                    Text(verbatim: title)
                    Text(verbatim: subtitle)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Spacer()

                if let bsdName = disk.bsdName {
                    if state.busyDisks.contains(bsdName) {
                        ProgressView()
                            .controlSize(.small)
                        Text("Formatting…")
                            .foregroundStyle(.secondary)
                    } else if !disk.readOnly {
                        Button(layout?.initialized == true ? "Erase…" : "Format…") { showingFormat.value = true }
                            .controlSize(.small)
                    }
                }
            }

            if let error = disk.localizedError {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .font(.callout)
                    .foregroundStyle(.orange)
            } else if let layout {
                if !layout.initialized {
                    Text("This disk has not been formatted yet.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .padding(.leading, 38)
                }

                ForEach(layout.volumes) { volume in
                    VolumeRow(volume: volume)
                        .padding(.leading, 38)
                }
            }
        }
        .padding(.vertical, 3)
        .sheet(isPresented: $showingFormat.value) {
            FormatSheet(target: target, disk: disk, initialized: layout?.initialized == true)
                .environmentObject(state)
        }
    }

    private var layout: DiskLayout? { state.layout(of: disk) }

    private var title: String {
        let model = disk.model.isEmpty ? String(localized: "Disk") : disk.model
        return "\(model) — \(disk.size.formattedSize)"
    }

    private var subtitle: String {
        var parts = ["LUN \(disk.lun)"]
        if let bsdName = disk.bsdName { parts.append(bsdName) }
        if disk.readOnly { parts.append(String(localized: "read-only")) }
        return parts.joined(separator: " · ")
    }
}

/// A volume of a disk, with the means to open, mount and unmount it.
struct VolumeRow: View {
    @EnvironmentObject private var state: AppState
    let volume: Volume

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: volume.mountPoint == nil ? "square.dashed" : "externaldrive.fill")
                .foregroundStyle(volume.mountPoint == nil ? Color.secondary : Color.accentColor)
                .frame(width: 18)

            Text(verbatim: volume.name.isEmpty ? volume.bsdName : volume.name)
                .lineLimit(1)

            Text(verbatim: volume.size.formattedSize)
                .font(.caption)
                .foregroundStyle(.secondary)

            Spacer()

            if volume.mountPoint != nil {
                Button("Show in Finder") { state.reveal(volume) }
                    .controlSize(.small)
                Button("Unmount") { state.unmount(volume) }
                    .controlSize(.small)
            } else {
                Text("Not mounted")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Button("Mount") { state.mount(volume) }
                    .controlSize(.small)
            }
        }
    }
}

/// Asks for a name and a file system, then formats a disk.
struct FormatSheet: View {
    @EnvironmentObject private var state: AppState
    @Environment(\.dismiss) private var dismiss
    let target: Target
    let disk: Disk
    let initialized: Bool

    @StateObject private var name = Box("iSCSI")
    @StateObject private var format = Box(VolumeFormat.apfs)

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 12) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.system(size: 30))
                    .foregroundStyle(.yellow)

                VStack(alignment: .leading, spacing: 4) {
                    Text(initialized ? "Erase this disk?" : "Format this disk?")
                        .font(.headline)
                    Text(verbatim: "\(disk.model) — \(disk.size.formattedSize) (\(disk.bsdName ?? ""))")
                        .foregroundStyle(.secondary)
                }
            }

            Text("All data on the disk will be deleted, on the server as well. This cannot be undone.")
                .fixedSize(horizontal: false, vertical: true)

            Form {
                TextField("Name:", text: $name.value)
                Picker("Format:", selection: $format.value) {
                    ForEach(VolumeFormat.allCases) { choice in
                        Text(verbatim: choice.title).tag(choice)
                    }
                }
            }

            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button(initialized ? "Erase" : "Format", role: .destructive) {
                    state.format(disk, of: target, as: format.value, name: trimmedName)
                    dismiss()
                }
                .disabled(trimmedName.isEmpty)
            }
        }
        .padding(20)
        .frame(width: 420)
    }

    private var trimmedName: String {
        name.value.trimmingCharacters(in: .whitespacesAndNewlines)
    }
}

/// The CHAP settings of a target.
struct AuthenticationSection: View {
    @EnvironmentObject private var state: AppState
    let target: Target

    @StateObject private var name = Box("")
    @StateObject private var secret = Box("")
    @StateObject private var targetName = Box("")
    @StateObject private var targetSecret = Box("")

    var body: some View {
        Section {
            Picker("Authentication", selection: method) {
                Text("Default").tag(InitiatorAuth.inherit)
                Text("None").tag(InitiatorAuth.none)
                Text("CHAP").tag(InitiatorAuth.chap)
            }

            if target.initiatorAuth == .chap {
                TextField("User name", text: $name.value)
                    .onSubmit(saveCredentials)

                SecureField("Password", text: $secret.value,
                            prompt: Text(target.hasInitiatorSecret ? "Saved in keychain" : "Required"))
                    .onSubmit(saveCredentials)

                Toggle("Verify the server as well (mutual CHAP)", isOn: mutual)

                if target.mutualCHAP {
                    TextField("Server user name", text: $targetName.value)
                        .onSubmit(saveCredentials)

                    SecureField("Server password", text: $targetSecret.value,
                                prompt: Text(target.hasTargetSecret ? "Saved in keychain" : "Required"))
                        .onSubmit(saveCredentials)
                }

                HStack {
                    Spacer()
                    Button("Save", action: saveCredentials)
                        .disabled(!changed)
                }
            }
        } header: {
            Text("Authentication")
        } footer: {
            if target.initiatorAuth == .inherit {
                Text("Uses the CHAP credentials from Settings, if any.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .onAppear(perform: load)
        .onChange(of: target.initiatorCHAPName) { _ in load() }
        .onChange(of: target.targetCHAPName) { _ in load() }
    }

    private func load() {
        name.value = target.initiatorCHAPName
        targetName.value = target.targetCHAPName
    }

    private var changed: Bool {
        name.value != target.initiatorCHAPName || !secret.value.isEmpty ||
        targetName.value != target.targetCHAPName || !targetSecret.value.isEmpty
    }

    private var method: Binding<InitiatorAuth> {
        Binding(get: { target.initiatorAuth },
                set: { state.update(target, ["InitiatorAuth": $0.rawValue]) })
    }

    private var mutual: Binding<Bool> {
        Binding(get: { target.mutualCHAP },
                set: { state.update(target, ["MutualCHAP": $0]) })
    }

    private func saveCredentials() {
        var settings: [String: Any] = ["InitiatorCHAPName": name.value]

        if !secret.value.isEmpty { settings["InitiatorSecret"] = secret.value }

        if target.mutualCHAP {
            settings["TargetCHAPName"] = targetName.value
            if !targetSecret.value.isEmpty { settings["TargetSecret"] = targetSecret.value }
        }

        state.update(target, settings)
        secret.value = ""
        targetSecret.value = ""
    }
}
