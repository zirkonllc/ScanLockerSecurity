//
//  TrustedDevicePairingLink.swift
//  ScanLocker
//
//  ================= WHAT THIS FILE IS =================
//  Pairing two devices in the same room, over the radio the owner picks.
//  The two find each other through a `PairingTransport`, which is an L2CAP
//  channel for Bluetooth and a Bonjour-advertised TCP socket for Wi-Fi. Everything below the pipe is the same on both: one shows
//  a six-digit PIN and the other types it, and the PIN authenticates the
//  exchange of the two public keys that every later transfer between them
//  rests on. Nothing here touches the vault; the outcome is handed to the
//  store, which writes the record.
//
//  ================= THE HANDSHAKE =================
//  The device showing the PIN is the host; the device typing it is the joiner.
//
//    1  joiner → host   HELLO      joiner's public key, joiner's nonce
//    2  host → joiner   CHALLENGE  pairing id, host's public key, host's
//                                  nonce, host's CPace point
//    3  joiner → host   PROVE      joiner's CPace point, then a tag over the
//                                  whole transcript keyed by the session key
//    4  host → joiner   ACCEPT     a tag over the same transcript under a
//                                  different label, or REJECT
//    5  host → joiner   INFO       the host's description of itself, sealed
//                                  under a key only the two static keys reach
//    6  joiner → host   INFO       the joiner's, the same way
//
//  The PIN authenticates through CPace, a balanced password-authenticated
//  key exchange (draft-irtf-cfrg-cpace, suite CPace255 with SHA-512). Both
//  sides hash the PIN with a session identifier they both contributed and
//  the channel identifier below, map the hash onto Curve25519 through
//  Field25519 and use that point as the generator of one Diffie-Hellman
//  exchange. Each CPace point on the air is a fresh random scalar times that
//  generator, so it is consistent with every PIN and tests none: a device
//  that pretends to be the host learns nothing it can try against candidate
//  PINs afterwards. A wrong PIN on either side gives a different generator,
//  an unrelated shared point and a tag that does not verify. The session
//  key is HKDF-SHA256 over the shared point with the transcript as salt,
//  and the two tags are HMAC-SHA256 under it. A shared point that is the
//  neutral element, which a low-order point produces, is refused before any
//  key is derived.
//
//  The joiner proves first, so a stranger who connects to the host learns
//  nothing keyed by the session before they have shown they hold the PIN.
//  The descriptions travel only after both sides have proved the PIN and
//  only sealed, so a device name is never on the air in the clear.
//
//  A PIN is shown once. The first handshake that starts and does not
//  complete retires it: a tag that does not verify, a connection that drops
//  after HELLO, a deadline that expires after HELLO, or anything unreadable
//  on the wire after HELLO. The host then stops advertising, tells the
//  joiner with REJECT where one is still connected and says so on its own
//  screen beside Show a New PIN. Under CPace a guess can only be tested by
//  attempting a handshake, so this bounds an attacker to one guess per shown
//  PIN. HELLO is the line, because the host sends nothing derived from the
//  PIN before it has HELLO in hand: a host waiting with nobody connected, or
//  with a joiner that connected and sent nothing, retires nothing and keeps
//  waiting, since nothing has been attempted against the PIN and a radio
//  that failed to connect should not cost one. Every wait for the other
//  side's next message has a twenty-second deadline, which under CPace bounds
//  only how long the other device may take to answer. Finding the other
//  device has no deadline; the person can see it is searching and Cancel
//  ends it.
//
//  Before the first pairing after each launch the link evaluates one of the
//  draft's published vectors through Field25519 and CryptoKit. It refuses
//  to pair when the result does not match, so arithmetic gone wrong on some
//  chip never derives a key. The refusal runs in every build and sends
//  nothing.
//
//  Both devices advertise as "ScanLocker-" plus four random letters, never
//  as the device's own name. The host shows its four letters under the PIN
//  so the joiner picks the right device in a room with more than one.
//

import Combine
import CryptoKit
import Foundation

@MainActor
final class TrustedDevicePairingLink: NSObject, ObservableObject {

    /// The Bonjour service the Wi-Fi pipe publishes. It is its own type, so a
    /// pairing never answers a browser looking for a transfer.
    static let bonjourType = "_sl-pair._tcp"
    static let handshakeDeadline: TimeInterval = 20
    /// The backstop over a remote joiner's reach. Every step of the remote
    /// pipe ends by a deadline of its own, and those add up to under this.
    static let remoteConnectDeadline: TimeInterval = 130
    static let pinLength = 6
    /// Ceiling on a sealed description before any of it is opened.
    static let maxInfoBytes = 512

    struct Outcome: Equatable {
        let pairingID: Data
        let myKeys: TrustedDeviceCrypto.KeyPair
        let theirPublicKey: Data
        let theirDescription: DeviceDescription
    }

    /// A device offering to pair. The transport resolves the identifier back
    /// to its own handle, so neither this link nor the screen holds a type
    /// belonging to one radio.
    typealias FoundDevice = PairingPeer

    enum Role { case host, join }

    // MARK: - What the screen reads

    @Published private(set) var status = ""
    @Published private(set) var errorText: String?
    @Published private(set) var found: [FoundDevice] = []
    @Published private(set) var outcome: Outcome?
    @Published private(set) var pinRetired = false
    /// True when the self-test refused to pair, so the screen shows neither
    /// a PIN nor a search.
    @Published private(set) var refused = false
    /// True from the invitation until the handshake ends, one way or the other.
    @Published private(set) var busy = false
    /// True when the chosen radio would not start. The screen reads this and
    /// returns to the step that picks a radio, so the other one is one tap
    /// away rather than a whole flow away.
    @Published private(set) var radioFailed = false
    /// The three digits the rendezvous gave a remote host, once they stand.
    @Published private(set) var remoteSlot: String?

    private(set) var pin = ""
    private(set) var deviceTag = ""
    private(set) var role: Role?
    /// Which radio this attempt runs on. The screen picks it before either
    /// side commits to showing or typing a PIN.
    private(set) var radio: PairingRadio = .nearby

    /// The nine digits a remote host reads aloud: the slot, then the PIN.
    var remoteCode: RemotePairingCode? {
        remoteSlot.flatMap { RemotePairingCode(slot: $0, pin: pin) }
    }

    // MARK: - Wire

    private enum MessageType: UInt8 {
        case hello = 0x01
        case challenge = 0x02
        case prove = 0x03
        case accept = 0x04
        case reject = 0x05
        case info = 0x06

        /// Fixed for every message but INFO, whose sealed body varies and is
        /// bounded instead.
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
        /// Host: connected, waiting for HELLO.
        case awaitingHello
        /// Joiner: HELLO sent, waiting for CHALLENGE.
        case awaitingChallenge
        /// Host: CHALLENGE sent, waiting for PROVE.
        case awaitingProve
        /// Joiner: PROVE sent, waiting for ACCEPT or REJECT.
        case awaitingAccept
        /// Both: PIN proved both ways, waiting for the other's description.
        case awaitingInfo
        case done
    }

    /// CPace's channel identifier and the first field of the transcript.
    /// It moved from v1 to v2 with the exchange, since the wire changed.
    private static let channelIdentifier = Data("scanlocker.trusted.pairing.v2".utf8)
    /// How long the last message of an attempt is given to leave before the
    /// session drops: the final INFO on success, REJECT on retirement. One
    /// second is many times a datagram's crossing between two devices in one
    /// room. finish and retire take the same bound.
    private static let lastMessageGrace: TimeInterval = 1
    /// The two sentences the wire can earn before any PIN is involved,
    /// written once.
    private static let unreadable = "This device could not read the other device\u{2019}s reply"
    private static let couldNotPrepare = "This device could not start pairing"
    private static let retiredReason: UInt8 = 0xFF
    /// The smallest AES-GCM box: nonce and tag around an empty message.
    private static let minSealedBytes = 12 + 16

    // MARK: - State

    private var phase: Phase = .idle
    private var myKeys = TrustedDeviceCrypto.KeyPair.generate()
    private var transport: PairingTransport?
    private var deadlineGeneration = 0
    private var hintGeneration = 0
    private var lifetimeGeneration = 0
    private var enteredPIN = ""

    /// How long a search may run in silence before the status says what to
    /// check. The search itself has no deadline; Cancel ends it.
    private static let stallHintAfter: TimeInterval = 30

    /// Fill or kill for the PIN a host shows. Five minutes is long enough to
    /// carry the code to the other iPhone, and it ends the one wait that
    /// otherwise held a live PIN advertised until the sheet closed. Show a
    /// New PIN mints another.
    private static let pinLifetime: TimeInterval = 300

    private var pairingID = Data()
    private var joinerPub = Data()
    private var joinerNonce = Data()
    private var hostPub = Data()
    private var hostNonce = Data()
    /// The two CPace points, host's then joiner's.
    private var hostPoint = Data()
    private var joinerPoint = Data()
    /// This side's scalar for the exchange, kept from its own point until
    /// the shared point is derived and forgotten with the session key.
    private var exchangeScalar: Curve25519.KeyAgreement.PrivateKey?
    private var sessionKey: SymmetricKey?

    // MARK: - Starting and stopping

    /// Show a PIN on this device and wait for the other one to connect.
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

    /// Look for a device that is showing a PIN.
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
        // Nothing is searched for on the remote route, so nothing is said.
        guard radio != .remote else { return }
        status = "Looking for a device that is showing a PIN."
        armStallHint("No device showing a PIN has been found yet. " + radio.checkLine)
    }

    /// Connect to the chosen device with the PIN it shows.
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

    /// Reach the device showing these nine digits. Each try runs on a fresh
    /// pipe, so nothing of a spent code is still standing under it. The
    /// deadline covers every step of the pipe and falls to the handshake's
    /// own once the two devices are connected.
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

    // MARK: - The handshake

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
        // Nothing is under way, or the pairing is already done, so this is a
        // straggler from an attempt that has ended and been reported. It
        // changes nothing.
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
            // The one byte always says retired; a REJECT is the host saying
            // this PIN is spent, whatever ended the attempt there.
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

    /// Sends this device's description, sealed under the pairing key. False
    /// means the pairing has already been failed and reported.
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
        // The last message needs a moment to leave before the pipe drops.
        transport?.resetConnection(after: Self.lastMessageGrace, readyForAnother: false)
    }

    /// Ends the attempt with its cause named first. On the host that has
    /// HELLO in hand the PIN is retired with it, since a handshake that
    /// started and did not complete has spent the PIN. Everywhere else, on
    /// the joiner and on a host that nobody has sent HELLO to, the attempt
    /// ends, the host goes back to waiting and the sentence says so. `cause`
    /// is the clause before the comma. The outcome is written once here.
    private func fail(_ cause: String) {
        if role == .host, phase == .awaitingProve || phase == .awaitingInfo {
            retire(cause: cause)
        } else {
            endAttempt("\(cause), so the pairing stopped.")
        }
    }

    /// The host's way out: advertising stops, the joiner still connected is
    /// told with REJECT and the screen says what happened beside Show a
    /// New PIN. The one byte of REJECT always reads retired.
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
        // REJECT needs the same moment to leave that finish gives the last
        // INFO. Without it the joiner sees a dropped connection and does not
        // learn the PIN is retired.
        endAttempt(message, disconnectAfter: told ? Self.lastMessageGrace : 0)
    }

    private func endAttempt(_ message: String, disconnectAfter grace: TimeInterval = 0) {
        deadlineGeneration += 1
        forgetExchange()
        // The joiner keeps browsing and needs a pipe that has not been torn
        // down for its next try. A host whose PIN is retired keeps none, since
        // it advertises nothing until Show a New PIN.
        transport?.resetConnection(after: grace,
                                   readyForAnother: role == .join || pinRetired == false)
        phase = .idle
        busy = false
        errorText = message
        status = role == .host && pinRetired == false ? "Waiting for the other device." : ""
        // A host that goes back to waiting is showing the PIN again, so the
        // wait for it to be typed takes a fresh bound. A host that reached
        // the proving phase has already retired and takes none.
        if role == .host, pinRetired == false, outcome == nil { armPINLifetime() }
    }

    /// Fill or kill: every wait for the other side's next message ends here
    /// if the message never comes.
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

    /// After thirty seconds of nothing, the status names what to check. It
    /// is a hint and never an abandonment: the search goes on until Cancel.
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

    /// Fill or kill for a PIN nobody types. The advertising stops and the
    /// code is spent, so the screen carries one sentence and Show a New PIN
    /// is the way on.
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

    /// One evaluation of the draft's vector per launch, before the first
    /// pairing. The answer is kept for every pairing after it. A
    /// mismatch means the field arithmetic or CryptoKit gave a wrong answer
    /// on this device. A key derived from a wrong answer would be a key
    /// nobody else can reach or one somebody else can, so nothing is sent.
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

    /// The self-test did not match. No radio starts, so nothing keyed by
    /// the arithmetic ever leaves this device.
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

    /// The radio could not be started at all: permission refused, or
    /// Bluetooth and Wi-Fi both off. Said plainly, so the screen never shows
    /// a search that is not happening.
    private func couldNotStart() {
        deadlineGeneration += 1
        hintGeneration += 1
        lifetimeGeneration += 1
        transport?.stopDiscovery()
        // A radio that cannot start may still be holding a connection that
        // arrived before it failed, and nothing else would close it once the
        // deadline below is stood down.
        transport?.resetConnection(after: 0, readyForAnother: false)
        phase = .idle
        busy = false
        status = ""
        // The remote pipe names the step that failed. Its host has no slot
        // left, so the code on screen is spent and a new one is the way on.
        errorText = remoteWords ?? radio.couldNotStartLine
        if radio == .remote, role == .host {
            pinRetired = true
        } else if radio != .remote {
            radioFailed = true
        }
    }

    /// The sentence of the remote pipe's last failed step, or nil.
    private var remoteWords: String? {
        (transport as? PairingRemoteTransport)?.words
    }

    // MARK: - Pieces

    /// The pipe this pairing runs over, stopped and rebuilt for each attempt
    /// so nothing from an abandoned one is still listening.
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

    /// False means the send failed and the attempt has already been ended
    /// and reported, so the caller returns without another word.
    private func send(_ type: MessageType, body: Data) -> Bool {
        var message = Data([type.rawValue])
        message.append(body)
        guard transport?.send(message) == true else {
            fail("This device could not send to the other one")
            return false
        }
        return true
    }

    /// This side's CPace point for a PIN: the generator for that PIN and
    /// this session, times a scalar drawn fresh for this handshake. The
    /// session identifier is the pairing id and both nonces, so both devices
    /// contributed to it and neither chose it alone. Nil when the device's
    /// arithmetic or randomness refused, which is not a state to pair in.
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

    /// The session key for this handshake. Nil when the shared point is the
    /// neutral element, which a low-order point from the other side
    /// produces, or when this side holds no scalar. The shared point itself
    /// never leaves this function.
    private func deriveSessionKey(theirPoint: Data) -> SymmetricKey? {
        guard let scalar = exchangeScalar,
              let shared = try? CPace255.multiply(scalar, times: theirPoint) else { return nil }
        return TrustedDeviceCrypto.pairingSessionKey(sharedPoint: shared, transcript: transcript())
    }

    private func forgetExchange() {
        exchangeScalar = nil
        sessionKey = nil
    }

    /// The channel identifier, then every field of HELLO and CHALLENGE, then
    /// the joiner's point, in the order they crossed the air.
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

    /// Four letters and digits with no look-alikes.
    private static func randomTag() -> String {
        let alphabet = Array("ABCDEFGHJKMNPQRSTUVWXYZ23456789")
        guard let bytes = try? TrustedDeviceCrypto.randomBytes(4) else { return "XXXX" }
        return String(bytes.map { alphabet[Int($0) % alphabet.count] })
    }
}

// MARK: - What the pipe reports

extension TrustedDevicePairingLink: PairingTransportDelegate {
    func pairingTransportDidConnect() {
        connected()
    }

    func pairingTransportIsConnecting() {
        if busy || role == .host { status = "Connecting." }
    }

    func pairingTransportDidDrop() {
        // A drop in the middle of the handshake is a failure the deadline
        // would otherwise report twenty seconds late.
        guard outcome == nil, phase != .idle else { return }
        // A remote joiner's pipe says which step of the reach failed.
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
        // Accepting only opens the handshake. Nothing keyed by the PIN leaves
        // this device until the joiner has proved the PIN.
        let accept = outcome == nil && pinRetired == false && busy == false
        if accept {
            // The deadline starts here, so a joiner that is accepted and then
            // never connects cannot leave this device busy forever.
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
