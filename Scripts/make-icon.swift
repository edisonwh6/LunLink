// Copyright (c) 2026, LunLink contributors
// SPDX-License-Identifier: BSD-2-Clause
//
// Draws the icon of the application at the sizes that an icon set calls for.
//
// usage: make-icon <iconset-directory>

import AppKit

func render(size: Int) -> Data? {
    guard let bitmap = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: size, pixelsHigh: size,
                                        bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                                        colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0),
          let context = NSGraphicsContext(bitmapImageRep: bitmap) else { return nil }

    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = context

    // The artwork sits on a rounded square that leaves a margin, as the
    // icons of macOS applications do
    let scale = CGFloat(size)
    let inset = scale * 0.1
    let square = NSRect(x: inset, y: inset, width: scale - 2 * inset, height: scale - 2 * inset)
    let background = NSBezierPath(roundedRect: square, xRadius: square.width * 0.225, yRadius: square.width * 0.225)

    let shadow = NSShadow()
    shadow.shadowColor = NSColor.black.withAlphaComponent(0.28)
    shadow.shadowOffset = NSSize(width: 0, height: -scale * 0.012)
    shadow.shadowBlurRadius = scale * 0.03
    shadow.set()

    NSColor(calibratedRed: 0.16, green: 0.42, blue: 0.86, alpha: 1).setFill()
    background.fill()

    NSShadow().set()
    NSGradient(colors: [NSColor(calibratedRed: 0.30, green: 0.62, blue: 0.98, alpha: 1),
                        NSColor(calibratedRed: 0.10, green: 0.32, blue: 0.78, alpha: 1)])?
        .draw(in: background, angle: -90)

    // A disk enclosure that is connected to a network.  The artwork is drawn
    // here from scratch: the symbols that come with the system are for use
    // inside applications, not for their icons.
    let side = square.width

    func point(_ x: CGFloat, _ y: CGFloat) -> NSPoint {
        NSPoint(x: square.minX + x * side, y: square.minY + y * side)
    }

    func box(_ x: CGFloat, _ y: CGFloat, _ width: CGFloat, _ height: CGFloat) -> NSRect {
        NSRect(origin: point(x, y), size: NSSize(width: width * side, height: height * side))
    }

    let ink = NSColor(calibratedRed: 0.13, green: 0.38, blue: 0.82, alpha: 1)

    // The enclosure, with two status lights and a slot
    NSColor.white.setFill()
    NSBezierPath(roundedRect: box(0.19, 0.50, 0.62, 0.27), xRadius: 0.06 * side, yRadius: 0.06 * side).fill()

    ink.setFill()
    NSBezierPath(ovalIn: box(0.265, 0.605, 0.06, 0.06)).fill()
    NSBezierPath(ovalIn: box(0.355, 0.605, 0.06, 0.06)).fill()
    NSBezierPath(roundedRect: box(0.49, 0.62, 0.25, 0.03), xRadius: 0.015 * side, yRadius: 0.015 * side).fill()

    // The network: a cable from the enclosure to a line with three stations
    let cable = NSBezierPath()
    cable.lineWidth = 0.042 * side
    cable.lineCapStyle = .round
    cable.lineJoinStyle = .round
    cable.move(to: point(0.50, 0.50))
    cable.line(to: point(0.50, 0.365))
    cable.move(to: point(0.25, 0.365))
    cable.line(to: point(0.75, 0.365))

    for x in [0.25, 0.50, 0.75] as [CGFloat] {
        cable.move(to: point(x, 0.365))
        cable.line(to: point(x, 0.29))
    }

    NSColor.white.setStroke()
    cable.stroke()

    NSColor.white.setFill()
    for x in [0.25, 0.50, 0.75] as [CGFloat] {
        NSBezierPath(ovalIn: box(x - 0.05, 0.19, 0.10, 0.10)).fill()
    }

    NSGraphicsContext.restoreGraphicsState()
    return bitmap.representation(using: .png, properties: [:])
}

guard CommandLine.arguments.count == 2 else {
    FileHandle.standardError.write("usage: make-icon <iconset-directory>\n".data(using: .utf8)!)
    exit(1)
}

let directory = URL(fileURLWithPath: CommandLine.arguments[1])
try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

for points in [16, 32, 128, 256, 512] {
    for factor in [1, 2] {
        let name = factor == 1 ? "icon_\(points)x\(points).png" : "icon_\(points)x\(points)@2x.png"

        guard let data = render(size: points * factor) else {
            FileHandle.standardError.write("unable to render \(name)\n".data(using: .utf8)!)
            exit(1)
        }
        try data.write(to: directory.appendingPathComponent(name))
    }
}
