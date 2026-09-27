//
//  TrustedPairingMarks.swift
//  ScanLocker
//
//  What the pairing screens draw around their words: the PIN the host shows,
//  the search the other side runs, and the steps under it.
//

import SwiftUI

/// The PIN the host reads out, large and centred on the sheet.
struct TrustedPINDigits: View {
    let pin: String

    /// Two groups of three, the way a system verification code is set.
    private var grouped: String {
        let half = pin.count / 2
        return pin.prefix(half) + " " + pin.dropFirst(half)
    }

    var body: some View {
        Text(grouped)
            .font(.system(size: 36, weight: .regular, design: .monospaced))
            .tracking(6)
            .foregroundColor(VaultTheme.ink)
            .frame(maxWidth: .infinity, alignment: .center)
            .accessibilityLabel("Pairing PIN \(pin.map(String.init).joined(separator: " "))")
    }
}


/// The search, drawn still: one device inside three grounds, each fainter than
/// the one within it. Nothing here moves, because the row beneath says what is
/// happening in words and carries the mark that turns.
struct PairingSearchMark: View {
    var body: some View {
        ZStack {
            Circle()
                .fill(VaultTheme.ink.opacity(0.04))
                .frame(width: 168, height: 168)
            Circle()
                .fill(VaultTheme.ink.opacity(0.07))
                .frame(width: 118, height: 118)
            Circle()
                .fill(VaultTheme.mist)
                .frame(width: 76, height: 76)
            Image(systemName: "iphone")
                .font(.system(size: 32, weight: .regular))
                .foregroundColor(VaultTheme.ink)
        }
        .frame(maxWidth: .infinity)
        .accessibilityHidden(true)
    }
}

/// What the app is doing now, over the things the owner does. The first row
/// carries the system's own indeterminate mark and the rest an open ring,
/// which no selector in this app uses, so none of them reads as a box to tick.
struct PairingStepList: View {
    let working: String
    let steps: [String]

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            row(working: true, text: working)
            ForEach(steps, id: \.self) { step in
                row(working: false, text: step)
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: VaultTheme.cardRect)
                .fill(VaultTheme.formGround)
        )
    }

    private func row(working: Bool, text: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Group {
                if working {
                    ProgressView().controlSize(.small)
                } else {
                    Image(systemName: "circle")
                        .font(.system(size: 15, weight: .regular))
                        .foregroundColor(VaultTheme.ink.opacity(0.25))
                }
            }
            .frame(width: 20, height: 20)
            .accessibilityHidden(true)
            Text(text)
                .font(VaultTheme.body(14))
                .foregroundColor(VaultTheme.accent)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
    }
}

extension PairingRadio {
    /// The two radios as tiles, each keeping the blue it is known by, drawn
    /// once for every popover that asks.
    static func tiles(current: PairingRadio? = nil,
                      onPick: @escaping (PairingRadio) -> Void) -> (DiscChoice, DiscChoice) {
        (DiscChoice(symbol: "wifi", name: PairingRadio.wiFi.name,
                    current: current == .wiFi,
                    tint: VaultTheme.wifiBlue) { onPick(.wiFi) },
         DiscChoice(name: PairingRadio.nearby.name,
                    current: current == .nearby,
                    action: { onPick(.nearby) }) {
             BluetoothGlyph(tint: VaultTheme.bluetoothBlue)
                 .frame(width: 17, height: 24)
         })
    }

    /// The remote route as the third tile, its globe in the wordmark blue. It
    /// is dead while safe mode has the route off. A caller passes a line when the tile
    /// has something to say.
    @MainActor
    static func remoteTile(enabled: Bool, line: String = "", current: Bool = false,
                           onPick: @escaping (PairingRadio) -> Void) -> DiscChoice {
        DiscChoice(symbol: "globe", name: PairingRadio.remote.name, line: line,
                   current: current, tint: VaultTheme.affirmBlue,
                   enabled: enabled && safeModeLoss(.remoteRoute) == nil) { onPick(.remote) }
    }
}

extension TrustedDevicePairingLink.Role {
    /// Share My PIN and Enter PIN as tiles the size of the radio tiles, so the
    /// popover's two steps stand at one size with buttons of one size. The
    /// remote route pairs under a code, so its tiles say Code.
    static func tiles(for radio: PairingRadio,
                      onPick: @escaping (TrustedDevicePairingLink.Role) -> Void)
        -> (DiscChoice, DiscChoice) {
        let word = radio == .remote ? "Code" : "PIN"
        return (DiscChoice(symbol: "arrow.up.right", name: "Share My \(word)") { onPick(.host) },
                DiscChoice(symbol: "circle.grid.3x3", name: "Enter \(word)") { onPick(.join) })
    }
}

/// The frame a pairing popover's step stands in: its title, a line under it, a
/// way back where a step stands behind it, and its tiles. The title row holds
/// the back button's height and the line holds its row on every step, blank
/// where a step has nothing to say, so the tiles start at one height on every
/// step.
private struct PairingPopoverStep: View {
    let title: String
    var line: String? = nil
    /// Why the radio picked last time would not start, said in red where the
    /// line stands, so the other radio is the next tap.
    var problem: String? = nil
    var onBack: (() -> Void)? = nil
    let first: DiscChoice
    let second: DiscChoice
    var third: DiscChoice? = nil
    var fourth: DiscChoice? = nil

    /// What the radio step says under its title. It holds for both radios,
    /// where naming a shared network would hold for Wi-Fi alone.
    static let radioLine = "Both devices must pick the same one."

    /// Three tiles stand one above another, each with its disc beside its name.
    private static func stacked(_ tile: DiscChoice) -> DiscChoice {
        var tile = tile
        tile.stacked = true
        return tile
    }

    var body: some View {
        VStack(spacing: 12) {
            ZStack {
                PopoverChoiceTitle(text: title)
                if let onBack {
                    HStack {
                        DialogBackButton(action: onBack)
                        Spacer(minLength: 0)
                    }
                }
            }
            .frame(minHeight: PageExitButton.side)
            // A space keeps the row's height on a step with no line.
            Text(problem ?? line ?? " ")
                .font(VaultTheme.body(12))
                .foregroundColor(problem == nil ? VaultTheme.settingsSubtle : VaultTheme.secureNo)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityHidden(problem == nil && line == nil)
            if let third {
                VStack(spacing: 10) {
                    Self.stacked(first)
                    Self.stacked(second)
                    Self.stacked(third)
                    if let fourth { Self.stacked(fourth) }
                }
            } else {
                HStack(alignment: .top, spacing: 10) {
                    first
                    second
                }
            }
        }
        .padding(16)
        .frame(width: PopoverChoiceList<EmptyView>.width)
        .presentationCompactAdaptation(.popover)
    }
}

/// Select Connection Method as a popover: the title over the three route
/// tiles. A tap outside closes it and keeps nothing, so it carries no Cancel of
/// its own.
struct PairingRadioPopover: View {
    var problem: String? = nil
    /// Whether the Internet tile is live for what this popover leads to.
    var remote: Bool = true
    var remoteLine: String = ""
    /// The radio this device was last sent on, ticked so the owner sees what
    /// they picked last. Every tile stays one tap away.
    var current: PairingRadio? = nil
    let onPick: (PairingRadio) -> Void

    var body: some View {
        let (wiFi, bluetooth) = PairingRadio.tiles(current: current, onPick: onPick)
        PairingPopoverStep(title: "Select Connection Method", line: PairingPopoverStep.radioLine,
                           problem: problem, first: wiFi, second: bluetooth,
                           third: PairingRadio.remoteTile(enabled: remote, line: remoteLine,
                                                          current: current == .remote,
                                                          onPick: onPick))
    }
}

/// The popover a paired device's row opens: the three routes a receive from
/// that device runs on, and Send All, which asks for its own route on a second
/// step behind a way back.
struct DeviceTransferPopover: View {
    var problem: String? = nil
    var current: PairingRadio? = nil
    /// Opens on the Send All step, for a send that asks again.
    var sending: Bool = false
    let onPick: (TransferDirection, PairingRadio) -> Void
    @State private var sendStep: Bool?

    var body: some View {
        if sendStep ?? sending {
            let (wiFi, bluetooth) = PairingRadio.tiles(current: current) { onPick(.send, $0) }
            PairingPopoverStep(title: "Send All", line: PairingPopoverStep.radioLine,
                               problem: problem, onBack: { sendStep = false },
                               first: wiFi, second: bluetooth,
                               third: PairingRadio.remoteTile(enabled: true, current: current == .remote) {
                                   onPick(.send, $0)
                               })
        } else {
            let (wiFi, bluetooth) = PairingRadio.tiles(current: current) { onPick(.receive, $0) }
            PairingPopoverStep(title: "Select Connection Method", line: PairingPopoverStep.radioLine,
                               problem: sending ? nil : problem, first: wiFi, second: bluetooth,
                               third: PairingRadio.remoteTile(enabled: true, current: current == .remote) {
                                   onPick(.receive, $0)
                               },
                               fourth: DiscChoice(symbol: "arrow.up.right", name: "Send All",
                                                  line: "Everything in ScanLocker, up to \(MigrateSource.ceilingName)") {
                                   sendStep = true
                               })
        }
    }
}

/// Pair a Device's popover: the radio, then which side this device takes, in
/// one popover at one size. The second answer opens the sheet on the PIN step
/// it leads to, and the chevron returns to the radio with nothing picked.
struct PairDevicePopover: View {
    var problem: String? = nil
    let onPick: (PairingRadio, TrustedDevicePairingLink.Role) -> Void
    @State private var radio: PairingRadio?

    var body: some View {
        if let radio {
            let (share, enter) = TrustedDevicePairingLink.Role.tiles(for: radio) { onPick(radio, $0) }
            PairingPopoverStep(title: "Pair Devices", onBack: { self.radio = nil },
                               first: share, second: enter)
        } else {
            let (wiFi, bluetooth) = PairingRadio.tiles { radio = $0 }
            PairingPopoverStep(title: "Select Connection Method", line: PairingPopoverStep.radioLine,
                               problem: problem, first: wiFi, second: bluetooth,
                               third: PairingRadio.remoteTile(enabled: true) { radio = $0 })
        }
    }
}

/// The last screen of a pairing: the two devices are paired, and the digits
/// both of them show.
struct PairingDoneStep: View {
    let device: TrustedDevice
    let onDone: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Devices Paired")
                    .font(VaultTheme.header(20))
                    .foregroundColor(VaultTheme.ink)
                    .fixedSize(horizontal: false, vertical: true)
            Text("Paired with \(device.name). Both devices can now send to each other.")
                .font(VaultTheme.body(15))
                .foregroundColor(VaultTheme.ink)
                .fixedSize(horizontal: false, vertical: true)
            VStack(alignment: .leading, spacing: 6) {
                Text("Pairing fingerprint")
                    .font(VaultTheme.body(13))
                    .foregroundColor(VaultTheme.accent)
                Text(device.fingerprint)
                    .font(.system(size: 17, weight: .semibold, design: .monospaced))
                    .foregroundColor(VaultTheme.ink)
            }
            Text("The other device shows the same digits.")
                    .font(VaultTheme.body(13))
                    .foregroundColor(VaultTheme.accent)
                    .fixedSize(horizontal: false, vertical: true)
            VaultFilledButton(title: "Done", fillsWidth: true, action: onDone)
        }
    }
}
