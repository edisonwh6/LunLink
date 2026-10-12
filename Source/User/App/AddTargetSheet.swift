// Copyright (c) 2026, LunLink contributors
// SPDX-License-Identifier: BSD-2-Clause

import SwiftUI

/// The state of the sheet that adds targets.
@MainActor
private final class AddTargetModel: ObservableObject {
    enum Mode: Hashable {
        case discover, manual
    }

    @Published var mode = Mode.discover

    // Discovery
    @Published var server = ""
    @Published var discovering = false
    @Published var discovered: [DiscoveredTarget]?
    @Published var chosen: Set<String> = []

    // Manual entry
    @Published var iqn = ""
    @Published var portal = ""

    // Credentials that apply to the targets that are added
    @Published var useCHAP = false
    @Published var chapName = ""
    @Published var chapSecret = ""

    @Published var adding = false
    @Published var failure: String?

    static func trimmed(_ string: String) -> String {
        string.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    var canAdd: Bool {
        if useCHAP && (Self.trimmed(chapName).isEmpty || chapSecret.isEmpty) { return false }

        switch mode {
        case .discover: return !chosen.isEmpty
        case .manual: return !Self.trimmed(iqn).isEmpty && !Self.trimmed(portal).isEmpty
        }
    }
}

/// Adds targets, either by asking a server for the targets that it offers
/// or by entering the name of a target by hand.
struct AddTargetSheet: View {
    @EnvironmentObject private var state: AppState
    @Environment(\.dismiss) private var dismiss
    @StateObject private var model = AddTargetModel()

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Add Target")
                .font(.title3.weight(.semibold))

            Picker("", selection: $model.mode) {
                Text("Find on Server").tag(AddTargetModel.Mode.discover)
                Text("Enter Manually").tag(AddTargetModel.Mode.manual)
            }
            .pickerStyle(.segmented)
            .labelsHidden()

            if model.mode == .discover {
                discoverPane
            } else {
                manualPane
            }

            if let failure = model.failure {
                Label(failure, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Divider()

            Toggle("The target requires a user name and password (CHAP)", isOn: $model.useCHAP)

            if model.useCHAP {
                Form {
                    TextField("User name:", text: $model.chapName)
                    SecureField("Password:", text: $model.chapSecret)
                }
            }

            HStack {
                if model.adding {
                    ProgressView()
                        .controlSize(.small)
                }
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Add") { add() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(!model.canAdd || model.adding)
            }
        }
        .padding(20)
        .frame(width: 520)
    }

    // MARK: Discovery

    private var discoverPane: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Enter the address of the iSCSI server (for instance a NAS) to list its targets.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            HStack {
                TextField("Address", text: $model.server, prompt: Text(verbatim: "192.168.1.10"))
                    .textFieldStyle(.roundedBorder)
                    .onSubmit(discover)

                Button("Find", action: discover)
                    .disabled(AddTargetModel.trimmed(model.server).isEmpty || model.discovering)
            }

            if model.discovering {
                HStack(spacing: 8) {
                    ProgressView()
                        .controlSize(.small)
                    Text("Asking the server for its targets…")
                        .foregroundStyle(.secondary)
                }
            } else if let discovered = model.discovered {
                if discovered.isEmpty {
                    Text("The server offers no targets to this Mac.")
                        .foregroundStyle(.secondary)
                } else {
                    List(discovered) { target in
                        Toggle(isOn: chosenBinding(target.iqn)) {
                            VStack(alignment: .leading, spacing: 1) {
                                Text(verbatim: target.iqn)
                                    .lineLimit(1)
                                    .truncationMode(.middle)

                                Text(verbatim: target.portals.map(\.endpoint).joined(separator: ", "))
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .lineLimit(1)

                                if state.target(target.iqn) != nil {
                                    Text("Already added")
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                            }
                        }
                        .disabled(state.target(target.iqn) != nil)
                    }
                    .frame(height: 150)
                    .border(.separator)
                }
            }
        }
    }

    private func chosenBinding(_ name: String) -> Binding<Bool> {
        Binding(get: { model.chosen.contains(name) },
                set: { if $0 { model.chosen.insert(name) } else { model.chosen.remove(name) } })
    }

    private func discover() {
        let address = AddTargetModel.trimmed(model.server)
        guard !address.isEmpty, !model.discovering else { return }

        model.discovering = true
        model.failure = nil
        model.discovered = nil

        Task {
            switch await state.discover(address) {
            case .success(let targets):
                model.discovered = targets
                model.chosen = Set(targets.map(\.iqn).filter { state.target($0) == nil })
            case .failure(let error):
                model.failure = error.message
            }
            model.discovering = false
        }
    }

    // MARK: Manual entry

    private var manualPane: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Enter the name of the target and the address of the server that provides it.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            Form {
                TextField("Target name:", text: $model.iqn, prompt: Text(verbatim: "iqn.2004-04.com.example:target"))
                TextField("Server address:", text: $model.portal, prompt: Text(verbatim: "192.168.1.10:3260"))
            }
        }
    }

    // MARK: Adding

    private func add() {
        model.adding = true
        model.failure = nil

        Task {
            let name = model.useCHAP ? AddTargetModel.trimmed(model.chapName) : nil
            let secret = model.useCHAP ? model.chapSecret : nil
            var succeeded = true

            switch model.mode {
            case .discover:
                for target in model.discovered ?? [] where model.chosen.contains(target.iqn) {
                    // A server that does not say where its target is to be
                    // found means the address that was asked
                    let portals = target.portals.isEmpty ? [AddTargetModel.trimmed(model.server)]
                                                         : target.portals.map(\.endpoint)
                    succeeded = await state.addTarget(target.iqn, portals: portals, chapName: name, chapSecret: secret) && succeeded
                }
            case .manual:
                succeeded = await state.addTarget(AddTargetModel.trimmed(model.iqn),
                                                  portals: [AddTargetModel.trimmed(model.portal)],
                                                  chapName: name, chapSecret: secret)
            }

            model.adding = false

            // Failures are shown right here rather than behind the sheet
            if succeeded {
                dismiss()
            } else if let error = state.error {
                model.failure = error.message
                state.error = nil
            }
        }
    }
}
