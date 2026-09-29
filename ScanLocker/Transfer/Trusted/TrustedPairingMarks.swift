import SwiftUI

struct TrustedPINDigits: View {
    let pin: String

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

    @MainActor
    static func remoteTile(enabled: Bool, line: String = "", current: Bool = false,
                           onPick: @escaping (PairingRadio) -> Void) -> DiscChoice {
        DiscChoice(symbol: "globe", name: PairingRadio.remote.name, line: line,
                   current: current, tint: VaultTheme.affirmBlue,
                   enabled: enabled && safeModeLoss(.remoteRoute) == nil) { onPick(.remote) }
    }
}

extension TrustedDevicePairingLink.Role {
    static func tiles(for radio: PairingRadio,
                      onPick: @escaping (TrustedDevicePairingLink.Role) -> Void)
        -> (DiscChoice, DiscChoice) {
        let word = radio == .remote ? "Code" : "PIN"
        return (DiscChoice(symbol: "arrow.up.right", name: "Share My \(word)") { onPick(.host) },
                DiscChoice(symbol: "circle.grid.3x3", name: "Enter \(word)") { onPick(.join) })
    }
}

private struct PairingPopoverStep: View {
    let title: String
    var line: String? = nil
    var problem: String? = nil
    var onBack: (() -> Void)? = nil
    let first: DiscChoice
    let second: DiscChoice
    var third: DiscChoice? = nil
    var fourth: DiscChoice? = nil

    static let radioLine = "Both devices must pick the same one."

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

struct PairingRadioPopover: View {
    var problem: String? = nil
    var remote: Bool = true
    var remoteLine: String = ""
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

struct DeviceTransferPopover: View {
    var problem: String? = nil
    var current: PairingRadio? = nil
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

struct PairingDoneStep: View {
    let device: TrustedDevice
    let onDone: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Devices Paired")
                    .font(VaultTheme.display(20))
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
