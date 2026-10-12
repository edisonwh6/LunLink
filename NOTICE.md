# Notices

**LunLink**, an iSCSI initiator for macOS
Copyright (c) 2026, LunLink contributors

## Origin

This software is based on *iSCSI Initiator for macOS* by Nareg Sinenian and
the contributors of the iscsi-osx project
(<https://github.com/iscsi-osx/iSCSIInitiator>),

    Copyright (c) 2016-2021, Nareg Sinenian
    All rights reserved.

which is distributed under the BSD 2-Clause License. The copyright notice,
the conditions and the disclaimer of that license are reproduced in
[LICENSE.md](LICENSE.md); they apply to this software as a whole, which is
distributed under the same license.

Roughly a third of the source lines stem from the original: above all the
login and negotiation of sessions, CHAP authentication, discovery, the types
and preferences, the definitions of the protocol data units, and the syntax
of `iscsictl`. Every file that contains code of the original carries the
copyright notice of the original at its top; files that have been changed
since name the contributors of this project as well. The following are new:
the user-space host bus adapter, the logical unit layer, the block export,
the disk manager, the launch agent support, the graphical application, the
launcher, the tests and the build.

The kernel extension, the Xcode project and the installer of the original are
not part of this software. Neither is the history of the original repository,
which remains available at the address above.

## No affiliation

This is an independent project. It is not affiliated with, endorsed by or
supported by the authors of the original, nor by Apple Inc. Problems with
this software are not theirs to solve.

## Third-party material

No third-party code is bundled.

* The original carried an implementation of CRC32C by Mark Adler. It is not
  part of this software, whose own implementation (`iSCSICRC32C.c`) uses the
  CRC instructions of the processor by way of compiler intrinsics.
* The application shows symbols that macOS provides (SF Symbols) in its user
  interface, at run time. None of them are redistributed, and none is used
  for the icon of the application, which is drawn by `Scripts/make-icon.swift`.
* The software uses frameworks that are part of macOS (among them
  CoreFoundation, Security, IOKit and SwiftUI) and tools that come with it
  (`hdiutil`, `diskutil`, `mount_nfs`, `launchctl`).

## Trademarks

Apple, Mac, macOS, Finder and SF Symbols are trademarks of Apple Inc.,
registered in the U.S. and other countries. Other names may be trademarks of
their respective owners. They are used here to describe what the software
works with, not to suggest any endorsement.
