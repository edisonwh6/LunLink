// Copyright (c) 2026, LunLink contributors
// SPDX-License-Identifier: BSD-2-Clause

import SwiftUI

/// The main window: the targets on the left, the selected target on the right.
struct ContentView: View {
    @EnvironmentObject private var state: AppState

    var body: some View {
        NavigationSplitView {
            sidebar
                .navigationSplitViewColumnWidth(min: 230, ideal: 270, max: 400)
        } detail: {
            if let target = state.target(state.selection) {
                TargetDetailView(target: target)
                    .id(target.iqn)
            } else {
                emptyState
            }
        }
        .navigationTitle("LunLink")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button {
                    state.showingAddTarget = true
                } label: {
                    Label("Add Target", systemImage: "plus")
                }
                .help("Add a target")
            }
        }
        .sheet(isPresented: $state.showingAddTarget) {
            AddTargetSheet()
                .environmentObject(state)
        }
        .alert(item: $state.error) { error in
            Alert(title: Text(error.title), message: Text(error.message), dismissButton: .default(Text("OK")))
        }
        .frame(minWidth: 780, minHeight: 500)
        #if DEBUG
        .onAppear { DebugSnapshot.install(state: state) }
        #endif
    }

    private var sidebar: some View {
        List(selection: $state.selection) {
            Section("Targets") {
                ForEach(state.targets) { target in
                    TargetRow(target: target, busy: state.busyTargets.contains(target.iqn))
                        .tag(target.iqn)
                        .contextMenu {
                            if target.connected {
                                Button("Disconnect") { state.confirmDisconnect(target) }
                            } else {
                                Button("Connect") { state.connect(target) }
                            }
                            Divider()
                            Button("Copy Name") {
                                NSPasteboard.general.clearContents()
                                NSPasteboard.general.setString(target.iqn, forType: .string)
                            }
                            Button("Remove…") { state.remove(target) }
                                .disabled(target.connected)
                        }
                }
            }
        }
        .listStyle(.sidebar)
        .safeAreaInset(edge: .bottom, spacing: 0) {
            DaemonStatusBar()
        }
    }

    private var emptyState: some View {
        VStack(spacing: 14) {
            Image(systemName: "externaldrive.badge.plus")
                .font(.system(size: 52, weight: .light))
                .foregroundStyle(.secondary)

            Text(state.targets.isEmpty ? "No Targets" : "No Target Selected")
                .font(.title2.weight(.semibold))

            Text("Add an iSCSI target to use its disks on this Mac.")
                .foregroundStyle(.secondary)

            Button("Add Target…") { state.showingAddTarget = true }
                .controlSize(.large)
                .keyboardShortcut(.defaultAction)
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

/// A target in the sidebar.
struct TargetRow: View {
    let target: Target
    let busy: Bool

    var body: some View {
        HStack(spacing: 9) {
            StatusDot(target: target)

            VStack(alignment: .leading, spacing: 1) {
                Text(target.displayName)
                    .lineLimit(1)
                    .truncationMode(.middle)

                Text(subtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }

            Spacer(minLength: 0)

            if busy {
                ProgressView()
                    .controlSize(.small)
            }
        }
        .padding(.vertical, 2)
    }

    private var subtitle: String {
        if let session = target.session {
            if session.recovering { return String(localized: "Reconnecting…") }
            let count = target.disks.count
            return count == 1 ? String(localized: "Connected · 1 disk") : String(localized: "Connected · \(count) disks")
        }
        return target.portals.first?.address ?? String(localized: "Not connected")
    }
}

/// Shows the state of a target as a colored dot.
struct StatusDot: View {
    let target: Target

    var body: some View {
        Circle()
            .fill(color)
            .frame(width: 9, height: 9)
            .overlay(Circle().strokeBorder(.primary.opacity(0.12), lineWidth: 0.5))
            .accessibilityLabel(Text(label))
    }

    private var color: Color {
        guard let session = target.session else { return Color.secondary.opacity(0.35) }
        return session.recovering ? .orange : .green
    }

    private var label: String {
        guard let session = target.session else { return String(localized: "Not connected") }
        return session.recovering ? String(localized: "Reconnecting…") : String(localized: "Connected")
    }
}

/// Shows whether the daemon is running, at the bottom of the sidebar.
struct DaemonStatusBar: View {
    @EnvironmentObject private var state: AppState

    var body: some View {
        VStack(spacing: 0) {
            Divider()

            HStack(spacing: 6) {
                Circle()
                    .fill(state.snapshot.daemonRunning ? Color.green : Color.red)
                    .frame(width: 7, height: 7)

                if !state.loaded {
                    Text("Starting…")
                } else if state.snapshot.daemonRunning {
                    Text("Daemon running")
                } else {
                    Text("Daemon not running")
                    Spacer()
                    Button("Start") { state.startDaemon() }
                        .controlSize(.small)
                }
                Spacer(minLength: 0)
            }
            .font(.caption)
            .foregroundStyle(.secondary)
            .padding(.horizontal, 12)
            .padding(.vertical, 7)
        }
        .background(.bar)
    }
}
