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

struct PairingSearchHeading: View {
    let waits: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Looking for a Device")
                .font(VaultTheme.header(26))
                .foregroundColor(VaultTheme.ink)
                .accessibilityAddTraits(.isHeader)
            if waits {
                Text("Waiting for another device to show a PIN...")
                    .font(VaultTheme.body(17))
                    .foregroundColor(VaultTheme.accent)
            }
        }
        .fixedSize(horizontal: false, vertical: true)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

struct PairingSearchMark: View {
    var body: some View {
        ZStack {
            Circle()
                .fill(VaultTheme.wifiBlue.opacity(0.10))
                .frame(width: 168, height: 168)
            Circle()
                .fill(VaultTheme.wifiBlue.opacity(0.20))
                .frame(width: 118, height: 118)
            Circle()
                .fill(VaultTheme.paper)
                .frame(width: 76, height: 76)
            phone
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 8)
        .accessibilityHidden(true)
    }

    private var phone: some View {
        let shell = RoundedRectangle(cornerRadius: 6, style: .continuous)
        return shell
            .fill(LinearGradient(colors: [VaultTheme.pressed, VaultTheme.popoverRow],
                                 startPoint: .topLeading, endPoint: .bottomTrailing))
            .overlay(shell.stroke(VaultTheme.ink, lineWidth: 3))
            .overlay(alignment: .top) {
                Capsule().fill(VaultTheme.ink).frame(width: 6, height: 2).padding(.top, 5)
            }
            .overlay(alignment: .bottom) {
                Capsule().fill(VaultTheme.ink).frame(width: 8, height: 2).padding(.bottom, 5)
            }
            .frame(width: 22, height: 38)
    }
}

struct PairingStepStrip: View {
    let stage: TrustedDevicePairingLink.Stage

    private static let steps = TrustedDevicePairingLink.Stage.allCases
    private static let dot: CGFloat = 12
    private static let halo: CGFloat = 22

    var body: some View {
        HStack(spacing: 0) {
            ForEach(Self.steps, id: \.self) { step in
                VStack(spacing: 6) {
                    mark(for: step)
                        .frame(width: Self.halo, height: Self.halo)
                    Text(step.name)
                        .font(step == stage ? VaultTheme.display(11) : VaultTheme.body(11))
                        .foregroundColor(step == stage ? VaultTheme.ink : VaultTheme.accent)
                        .lineLimit(1)
                }
                .frame(maxWidth: .infinity)
            }
        }
        .background(alignment: .top) {
            GeometryReader { geo in
                let column = geo.size.width / CGFloat(Self.steps.count)
                let reach = column * (CGFloat(stage.rawValue) + 0.5)
                Rectangle()
                    .fill(VaultTheme.ink.opacity(0.25))
                    .frame(width: geo.size.width - column, height: 2)
                    .offset(x: column / 2, y: Self.halo / 2 - 1)
                Rectangle()
                    .fill(VaultTheme.ink)
                    .frame(width: max(0, reach - column / 2), height: 2)
                    .offset(x: column / 2, y: Self.halo / 2 - 1)
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Step \(stage.rawValue + 1) of \(Self.steps.count), \(stage.name)")
    }

    @ViewBuilder
    private func mark(for step: TrustedDevicePairingLink.Stage) -> some View {
        if step < stage {
            Circle().fill(VaultTheme.ink).frame(width: Self.dot, height: Self.dot)
        } else if step == stage {
            ZStack {
                Circle().fill(VaultTheme.wordmarkOrange.opacity(0.22))
                Circle().fill(VaultTheme.wordmarkOrange).frame(width: Self.dot, height: Self.dot)
            }
        } else {
            Circle()
                .fill(VaultTheme.paper)
                .overlay(Circle().stroke(VaultTheme.ink.opacity(0.25), lineWidth: 2))
                .frame(width: Self.dot, height: Self.dot)
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
