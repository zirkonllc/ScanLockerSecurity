import Combine
import CryptoKit
import Foundation

@MainActor
final class TrustedDevicePairingLink: NSObject, ObservableObject {
    static let bonjourType = "_sl-pair._tcp"
    static let handshakeDeadline: TimeInterval = 20
    static let remoteConnectDeadline: TimeInterval = 130
    static let pinLength = 6
    static let maxInfoBytes = 512

    struct Outcome: Equatable {
        let pairingID: Data
        let myKeys: TrustedDeviceCrypto.KeyPair
        let theirPublicKey: Data
        let theirDescription: DeviceDescription
    }

    typealias FoundDevice = PairingPeer

    enum Role { case host, join }

    @Published private(set) var status = ""
    @Published private(set) var errorText: String?
    @Published private(set) var found: [FoundDevice] = []
    @Published private(set) var outcome: Outcome?
    @Published private(set) var pinRetired = false
    @Published private(set) var refused = false
    @Published private(set) var busy = false
    @Published private(set) var radioFailed = false
    @Published private(set) var remoteSlot: String?

    private(set) var pin = ""
    private(set) var deviceTag = ""
    private(set) var role: Role?
    private(set) var radio: PairingRadio = .nearby

    var remoteCode: RemotePairingCode? {
        remoteSlot.flatMap { RemotePairingCode(slot: $0, pin: pin) }
    }

    private enum MessageType: UInt8 {
        case hello = 0x01
        case challenge = 0x02
        case prove = 0x03
        case accept = 0x04
        case reject = 0x05
        case info = 0x06

        var bodyLength: Int? {
            switch self {
            case .hello: return 32 + 16
            case .challenge: return 16 + 32 + 16 + 32
            case .prove: return 32 + 32
            case .accept: return 32
            case .reject: return 1
            case .info: return nil
            }
        }
    }

    private enum Phase {
        case idle
        case awaitingHello
        case awaitingChallenge
        case awaitingProve
        case awaitingAccept
        case awaitingInfo
        case done
    }

    private static let channelIdentifier = Data("scanlocker.trusted.pairing.v2".utf8)
    private static let lastMessageGrace: TimeInterval = 1
    private static let unreadable = "This device could not read the other device\u{2019}s reply"
    private static let couldNotPrepare = "This device could not start pairing"
    private static let retiredReason: UInt8 = 0xFF
    private static let minSealedBytes = 12 + 16

    private var phase: Phase = .idle
    private var myKeys = TrustedDeviceCrypto.KeyPair.generate()
    private var transport: PairingTransport?
    private var deadlineGeneration = 0
    private var hintGeneration = 0
    private var lifetimeGeneration = 0
    private var enteredPIN = ""

    private static let stallHintAfter: TimeInterval = 30

    private static let pinLifetime: TimeInterval = 300

    private var pairingID = Data()
    private var joinerPub = Data()
    private var joinerNonce = Data()
    private var hostPub = Data()
    private var hostNonce = Data()
    private var hostPoint = Data()
    private var joinerPoint = Data()
    private var exchangeScalar: Curve25519.KeyAgreement.PrivateKey?
    private var sessionKey: SymmetricKey?

    func startHosting(radio: PairingRadio) {
        stop()
        self.radio = radio
        role = .host
        guard arithmeticStands() else {
            refuseToPair()
            return
        }
        pin = VaultPIN.randomCode()
        deviceTag = Self.randomTag()
        myKeys = .generate()
        pinRetired = false
        openTransport().startAdvertising(tag: deviceTag)
        phase = .idle
        status = "Waiting for the other device."
        armStallHint(radio == .remote
            ? "Still waiting. The other device picks Internet where it pairs a device, then types this code."
            : "Still waiting. On the other device, tap Pair a Device, then Enter PIN, and pick ScanLocker-\(deviceTag).")
        armPINLifetime()
    }

    func startBrowsing(radio: PairingRadio) {
        stop()
        self.radio = radio
        role = .join
        pinRetired = false
        guard arithmeticStands() else {
            refuseToPair()
            return
        }
        deviceTag = Self.randomTag()
        myKeys = .generate()
        openTransport().startBrowsing(tag: deviceTag)
        phase = .idle
        guard radio != .remote else { return }
        status = "Looking for a device that is showing a PIN."
        armStallHint("No device showing a PIN has been found yet. " + radio.checkLine)
    }

    func join(_ device: FoundDevice, pin: String) {
        guard role == .join, let transport, busy == false, outcome == nil else { return }
        enteredPIN = pin
        errorText = nil
        pinRetired = false
        busy = true
        phase = .awaitingChallenge
        status = "Connecting to ScanLocker-\(device.tag)."
        transport.connect(to: device, timeout: Self.handshakeDeadline)
        armDeadline()
    }

    func joinRemote(code: RemotePairingCode) {
        guard radio == .remote, role == .join, busy == false, outcome == nil else { return }
        transport?.stop()
        openTransport().startBrowsing(tag: deviceTag)
        enteredPIN = code.pin
        errorText = nil
        pinRetired = false
        busy = true
        phase = .awaitingChallenge
        status = "Reaching the other device."
        transport?.connect(to: PairingPeer(id: code.slot, tag: ""), timeout: Self.remoteConnectDeadline)
        armDeadline(Self.remoteConnectDeadline)
    }

    func stop() {
        deadlineGeneration += 1
        hintGeneration += 1
        lifetimeGeneration += 1
        transport?.stop()
        transport = nil
        found = []
        busy = false
        radioFailed = false
        remoteSlot = nil
        phase = .idle
        status = ""
        errorText = nil
        outcome = nil
        refused = false
        forgetExchange()
    }

    private func connected() {
        guard outcome == nil else { return }
        switch role {
        case .host:
            guard phase == .awaitingHello else { return }
            status = "The other device connected."
            armDeadline()
        case .join:
            guard phase == .awaitingChallenge else { return }
            guard let nonce = try? TrustedDeviceCrypto.randomBytes(16) else {
                fail("This device did not supply random numbers")
                return
            }
            joinerPub = myKeys.publicKey
            joinerNonce = nonce
            guard send(.hello, body: joinerPub + joinerNonce) else { return }
            status = "Connected. Proving the \(radio.secretWord)."
            armDeadline()
        case nil:
            break
        }
    }

    private func received(_ data: Data) {
        guard phase != .idle, phase != .done, outcome == nil else { return }
        guard let first = data.first, let type = MessageType(rawValue: first) else {
            fail(Self.unreadable)
            return
        }
        let body = data.dropFirst()
        if let expected = type.bodyLength {
            guard body.count == expected else {
                fail(Self.unreadable)
                return
            }
        } else {
            guard body.count >= Self.minSealedBytes, body.count <= Self.maxInfoBytes else {
                fail(Self.unreadable)
                return
            }
        }

        switch (role, phase, type) {
        case (.host, .awaitingHello, .hello):
            joinerPub = Data(body.prefix(32))
            joinerNonce = Data(body.suffix(16))
            guard TrustedDeviceCrypto.isValidPublicKey(joinerPub),
                  let id = try? TrustedDeviceCrypto.randomBytes(TrustedDeviceCrypto.pairingIDLength),
                  let nonce = try? TrustedDeviceCrypto.randomBytes(16) else {
                fail(Self.couldNotPrepare)
                return
            }
            pairingID = id
            hostPub = myKeys.publicKey
            hostNonce = nonce
            guard let point = exchangePoint(pin: pin) else {
                fail(Self.couldNotPrepare)
                return
            }
            hostPoint = point
            guard send(.challenge, body: pairingID + hostPub + hostNonce + hostPoint) else { return }
            phase = .awaitingProve
            status = "Waiting for the other device to enter the \(radio.secretWord)."
            armDeadline()

        case (.join, .awaitingChallenge, .challenge):
            var offset = body.startIndex
            func take(_ n: Int) -> Data {
                let slice = Data(body[offset..<offset + n]); offset += n; return slice
            }
            pairingID = take(16)
            hostPub = take(32)
            hostNonce = take(16)
            hostPoint = take(32)
            guard TrustedDeviceCrypto.isValidPublicKey(hostPub), let point = exchangePoint(pin: enteredPIN) else {
                fail(Self.couldNotPrepare)
                return
            }
            joinerPoint = point
            guard let key = deriveSessionKey(theirPoint: hostPoint) else {
                fail(CPace255.lowOrderRefusal)
                return
            }
            sessionKey = key
            guard send(.prove, body: joinerPoint + tag("join", key: key)) else { return }
            phase = .awaitingAccept
            status = "\(radio == .remote ? "Code" : "PIN") sent. Waiting for the other device."
            armDeadline()

        case (.host, .awaitingProve, .prove):
            joinerPoint = Data(body.prefix(32))
            let proof = Data(body.suffix(32))
            guard let key = deriveSessionKey(theirPoint: joinerPoint) else {
                fail(CPace255.lowOrderRefusal)
                return
            }
            sessionKey = key
            if validTag(proof, label: "join", key: key) {
                guard send(.accept, body: tag("host", key: key)) else { return }
                guard sendInfo() else { return }
                phase = .awaitingInfo
                status = "\(radio == .remote ? "Code" : "PIN") accepted. Exchanging device details."
                armDeadline()
            } else {
                fail("The other device entered a different \(radio.secretWord)")
            }

        case (.join, .awaitingAccept, .accept):
            guard let key = sessionKey, validTag(Data(body), label: "host", key: key) else {
                fail("The other device did not prove it holds the \(radio.secretWord)")
                return
            }
            guard sendInfo() else { return }
            phase = .awaitingInfo
            status = "\(radio == .remote ? "Code" : "PIN") accepted. Exchanging device details."
            armDeadline()

        case (.join, .awaitingAccept, .reject):
            pinRetired = true
            endAttempt("The other device retired its \(radio.secretWord), so the pairing stopped. Ask them to show a new one.")

        case (_, .awaitingInfo, .info):
            guard let key = pairingKey(),
                  let json = try? TransferCrypto.open(Data(body), key: key),
                  let description = try? JSONDecoder().decode(DeviceDescription.self, from: json) else {
                fail("The other device's device details would not open")
                return
            }
            finish(theirPublicKey: theirPublicKey, description: description.clamped())

        default:
            fail("The other device answered out of turn")
        }
    }

    private func sendInfo() -> Bool {
        guard let key = pairingKey(),
              let json = try? JSONEncoder().encode(DeviceDescription.thisDevice),
              let sealed = try? TransferCrypto.seal(json, key: key),
              sealed.count <= Self.maxInfoBytes else {
            fail("This device could not prepare its device details")
            return false
        }
        return send(.info, body: sealed)
    }

    private var theirPublicKey: Data {
        role == .host ? joinerPub : hostPub
    }

    private func pairingKey() -> SymmetricKey? {
        try? TrustedDeviceCrypto.pairingKey(myPrivate: myKeys.privateKey,
                                            theirPublic: theirPublicKey,
                                            transcript: transcript())
    }

    private func finish(theirPublicKey: Data, description: DeviceDescription) {
        deadlineGeneration += 1
        phase = .done
        busy = false
        status = "Paired."
        outcome = Outcome(pairingID: pairingID, myKeys: myKeys,
                          theirPublicKey: theirPublicKey, theirDescription: description)
        forgetExchange()
        transport?.stopDiscovery()
        transport?.resetConnection(after: Self.lastMessageGrace, readyForAnother: false)
    }

    private func fail(_ cause: String) {
        if role == .host, phase == .awaitingProve || phase == .awaitingInfo {
            retire(cause: cause)
        } else {
            endAttempt("\(cause), so the pairing stopped.")
        }
    }

    private func retire(cause: String) {
        retire(saying: radio == .remote
            ? "\(cause), so this code is retired. Tap Show a New Code to start again."
            : "\(cause), so this PIN is retired. Tap Show a New PIN to start again.")
    }

    private func retire(saying message: String) {
        pinRetired = true
        lifetimeGeneration += 1
        transport?.stopAdvertising()
        let told = transport?.send(Data([MessageType.reject.rawValue, Self.retiredReason])) == true
        endAttempt(message, disconnectAfter: told ? Self.lastMessageGrace : 0)
    }

    private func endAttempt(_ message: String, disconnectAfter grace: TimeInterval = 0) {
        deadlineGeneration += 1
        forgetExchange()
        transport?.resetConnection(after: grace,
                                   readyForAnother: role == .join || pinRetired == false)
        phase = .idle
        busy = false
        errorText = message
        status = role == .host && pinRetired == false ? "Waiting for the other device." : ""
        if role == .host, pinRetired == false, outcome == nil { armPINLifetime() }
    }

    private func armDeadline(_ given: TimeInterval? = nil) {
        let seconds = given ?? Self.handshakeDeadline
        deadlineGeneration += 1
        let generation = deadlineGeneration
        Task { @MainActor in
            try? await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
            guard generation == deadlineGeneration, outcome == nil, phase != .idle else { return }
            fail(seconds == Self.handshakeDeadline
                 ? "The other device did not answer within twenty seconds"
                 : "The other device could not be reached in time")
        }
    }

    private func armStallHint(_ message: String) {
        hintGeneration += 1
        let generation = hintGeneration
        Task { @MainActor in
            try? await Task.sleep(nanoseconds: UInt64(Self.stallHintAfter * 1_000_000_000))
            guard generation == hintGeneration, outcome == nil, phase == .idle, busy == false,
                  errorText == nil, role == .host || found.isEmpty else { return }
            status = message
        }
    }

    private func armPINLifetime() {
        lifetimeGeneration += 1
        let generation = lifetimeGeneration
        Task { @MainActor in
            try? await Task.sleep(nanoseconds: UInt64(Self.pinLifetime * 1_000_000_000))
            guard generation == lifetimeGeneration, outcome == nil, role == .host,
                  pinRetired == false, busy == false, phase == .idle else { return }
            retire(saying: radio == .remote
                ? PairingRemoteTransport.lifetimeWords
                : "Pairing waited too long, so this PIN is no longer valid. Start pairing again.")
        }
    }

    private static var arithmeticVerified: Bool?

    private func arithmeticStands() -> Bool {
        if let verified = Self.arithmeticVerified { return verified }
        let verified = CPace255.selfTest()
        Self.arithmeticVerified = verified
        #if DEBUG
        NSLog("ScanLocker pairing probe, selfTest %@:\n%@", verified ? "passed" : "FAILED", CPace255.probeReport())
        #endif
        return verified
    }

    private func refuseToPair() {
        deadlineGeneration += 1
        hintGeneration += 1
        lifetimeGeneration += 1
        phase = .idle
        busy = false
        refused = true
        status = ""
        errorText = "This device's pairing arithmetic did not pass its check, so it will not pair. Nothing was sent."
    }

    private func couldNotStart() {
        deadlineGeneration += 1
        hintGeneration += 1
        lifetimeGeneration += 1
        transport?.stopDiscovery()
        transport?.resetConnection(after: 0, readyForAnother: false)
        phase = .idle
        busy = false
        status = ""
        errorText = remoteWords ?? radio.couldNotStartLine
        if radio == .remote, role == .host {
            pinRetired = true
        } else if radio != .remote {
            radioFailed = true
        }
    }

    private var remoteWords: String? {
        (transport as? PairingRemoteTransport)?.words
    }

    @discardableResult
    private func openTransport() -> PairingTransport {
        let made: PairingTransport = switch radio {
        case .nearby: PairingBluetoothTransport()
        case .wiFi:   PairingWiFiTransport(bonjourType: Self.bonjourType)
        case .remote: remoteTransport()
        }
        made.delegate = self
        transport = made
        return made
    }

    private func remoteTransport() -> PairingRemoteTransport {
        let made = PairingRemoteTransport()
        made.onSlot = { [weak self] in self?.remoteSlot = $0 }
        return made
    }

    private func send(_ type: MessageType, body: Data) -> Bool {
        var message = Data([type.rawValue])
        message.append(body)
        guard transport?.send(message) == true else {
            fail("This device could not send to the other one")
            return false
        }
        return true
    }

    private func exchangePoint(pin: String) -> Data? {
        let sessionID = pairingID + joinerNonce + hostNonce
        guard let generator = CPace255.generator(prs: Data(pin.utf8), ci: Self.channelIdentifier, sid: sessionID) else {
            return nil
        }
        let scalar = Curve25519.KeyAgreement.PrivateKey()
        guard let point = try? CPace255.multiply(scalar, times: generator) else { return nil }
        exchangeScalar = scalar
        return point
    }

    private func deriveSessionKey(theirPoint: Data) -> SymmetricKey? {
        guard let scalar = exchangeScalar,
              let shared = try? CPace255.multiply(scalar, times: theirPoint) else { return nil }
        return TrustedDeviceCrypto.pairingSessionKey(sharedPoint: shared, transcript: transcript())
    }

    private func forgetExchange() {
        exchangeScalar = nil
        sessionKey = nil
    }

    private func transcript() -> Data {
        var t = Self.channelIdentifier
        t.append(joinerPub)
        t.append(joinerNonce)
        t.append(pairingID)
        t.append(hostPub)
        t.append(hostNonce)
        t.append(hostPoint)
        t.append(joinerPoint)
        return t
    }

    private func tag(_ label: String, key: SymmetricKey) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: Data(label.utf8) + transcript(), using: key))
    }

    private func validTag(_ tag: Data, label: String, key: SymmetricKey) -> Bool {
        HMAC<SHA256>.isValidAuthenticationCode(tag, authenticating: Data(label.utf8) + transcript(), using: key)
    }

    private static func randomTag() -> String {
        let alphabet = Array("ABCDEFGHJKMNPQRSTUVWXYZ23456789")
        guard let bytes = try? TrustedDeviceCrypto.randomBytes(4) else { return "XXXX" }
        return String(bytes.map { alphabet[Int($0) % alphabet.count] })
    }
}

extension TrustedDevicePairingLink: PairingTransportDelegate {
    func pairingTransportDidConnect() {
        connected()
    }

    func pairingTransportIsConnecting() {
        if busy || role == .host { status = "Connecting." }
    }

    func pairingTransportDidDrop() {
        guard outcome == nil, phase != .idle else { return }
        if role == .join, phase == .awaitingChallenge, let said = remoteWords {
            endAttempt(said)
        } else {
            fail("The connection to the other device dropped")
        }
    }

    func pairingTransport(didReceive message: Data) {
        received(message)
    }

    func pairingTransport(didUpdate peers: [PairingPeer]) {
        found = peers
        if busy == false, peers.isEmpty == false { status = "" }
    }

    func pairingTransportShouldAccept() -> Bool {
        let accept = outcome == nil && pinRetired == false && busy == false
        if accept {
            busy = true
            phase = .awaitingHello
            armDeadline()
        }
        return accept
    }

    func pairingTransportCouldNotStart() {
        couldNotStart()
    }
}
