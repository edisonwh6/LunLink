// Copyright (c) 2026, LunLink contributors
// SPDX-License-Identifier: BSD-2-Clause

import SwiftUI

/// Holds the local state of a view.
///
/// Views would ordinarily declare such state with `@State`.  As of the
/// macOS 27 SDK that attribute is implemented by a compiler plug-in which
/// ships with Xcode but not with the Command Line Tools, so in order for
/// the application to build with either, views keep their state in boxes
/// that they own through `@StateObject`.
final class Box<Value>: ObservableObject {
    @Published var value: Value

    init(_ value: Value) {
        self.value = value
    }
}
