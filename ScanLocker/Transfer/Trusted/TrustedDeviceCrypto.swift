//
//  TrustedDeviceCrypto.swift
//  ScanLocker
//
//  ================= WHAT THIS FILE IS =================
//  Every key a trusted device pairing produces or uses, in one place. Pure
//  functions: no storage, no UI, no network. The store, the pairing link and
//  the transfer link call these; the views never touch them.
//
//  ================= THE KEYS =================
//  Pairing gives each of the two devices a Curve25519 key pair of its own,
//  made for this pairing and used for nothing else, and the other device's
//  public half. The private half never leaves the sealed file it is written
//  to. From the two static keys both devices reach the same shared secret,
//  and every key below is derived from that secret with HKDF under a label
//  that names its one job, so a key for the channel can never be mistaken
//  for a key for the envelope.
//
//    transfer key   authenticates the handshake of one transfer, mixed with
//                   the salt that transfer minted, so no two transfers share
//                   a key
//    envelope key   wraps the master key inside the envelope, mixed with the
//                   envelope's own salt, so the envelope opens on the one
//                   device it was sealed for and nowhere else
//    pairing key    seals the two device descriptions exchanged at the end of
//                   pairing, mixed with the pairing transcript, so a device
//                   name is never on the air in the clear
//
//  The fingerprint is twenty digits both devices compute from the same two
//  public keys and the pairing identifier. The information sheet shows it,
//  so the two people can read it to each other if they ever want to be sure
//  the two records describe the same pairing.
//

import CryptoKit
import Foundation
import Security

/// `nonisolated`, like `VaultPIN`: derivation runs wherever the caller runs,
/// and this project's default isolation is the main actor.
nonisolated enum TrustedDeviceError: LocalizedError, Equatable {
    case randomnessUnavailable
    case keyMalformed
    case storeWriteFailed
    case recordsSuspect
    /// A shared point that is the neutral element, which a low-order point
    /// from the other side produces. It is refused before any key is derived.
    case lowOrderPoint

    var errorDescription: String? {
        switch self {
        case .randomnessUnavailable:
            return "This device did not supply random numbers, so nothing was created."
        case .keyMalformed:
            return "This device could not read the other device\u{2019}s reply. Check that both run the latest ScanLocker."
        case .lowOrderPoint:
            return "\(CPace255.lowOrderRefusal), so the pairing stopped."
        case .storeWriteFailed:
            return "The change to Paired Devices was not saved."
        case .recordsSuspect:
            return "Paired Devices can\u{2019}t be opened on this device. Remove them on the Security page before adding a device."
        }
    }
}

nonisolated enum TrustedDeviceCrypto {

    static let pairingIDLength = 16
    static let publicKeyLength = 32
    static let saltLength = 16

    private static let fingerprintInfo = Data("ScanLocker trusted device fingerprint v1".utf8)
    private static let transferInfo = Data("scanlocker.transfer.trusted.v1".utf8)
    private static let envelopeInfo = Data("scanlocker.transfer.envelope.v1".utf8)
    private static let bluetoothOuterInfo = Data("scanlocker.bluetooth.outer.record.v1".utf8)
    private static let pairingInfo = Data("scanlocker.trusted.pairing.v1".utf8)
    private static let pairingSessionInfo = Data("scanlocker.trusted.pairing.v2.session".utf8)

    // MARK: - Randomness

    static func randomBytes(_ count: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        guard status == errSecSuccess else { throw TrustedDeviceError.randomnessUnavailable }
        return Data(bytes)
    }

    // MARK: - Keys

    struct KeyPair: Equatable {
        let privateKey: Data
        let publicKey: Data

        static func generate() -> KeyPair {
            let key = Curve25519.KeyAgreement.PrivateKey()
            return KeyPair(privateKey: key.rawRepresentation,
                           publicKey: key.publicKey.rawRepresentation)
        }
    }

    /// Whether these 32 bytes load as a Curve25519 public key.
    static func isValidPublicKey(_ raw: Data) -> Bool {
        raw.count == publicKeyLength
            && (try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: raw)) != nil
    }

    private static func derive(myPrivate: Data, theirPublic: Data, salt: Data, info: Data) throws -> SymmetricKey {
        let mine: Curve25519.KeyAgreement.PrivateKey
        let theirs: Curve25519.KeyAgreement.PublicKey
        do {
            mine = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: myPrivate)
            theirs = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: theirPublic)
        } catch {
            throw TrustedDeviceError.keyMalformed
        }
        let secret = try mine.sharedSecretFromKeyAgreement(with: theirs)
        return secret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt,
                                              sharedInfo: info, outputByteCount: 32)
    }

    /// The key that authenticates one transfer's handshake. The salt is the
    /// one the sender minted for that transfer.
    static func transferKey(myPrivate: Data, theirPublic: Data, salt: Data) throws -> SymmetricKey {
        try derive(myPrivate: myPrivate, theirPublic: theirPublic, salt: salt, info: transferInfo)
    }

    /// The key that binds the Bluetooth outer channel to one pairing record.
    /// The pairing identifier is the salt, and no other key uses this label.
    static func bluetoothOuterKey(myPrivate: Data, theirPublic: Data, pairingID: Data) throws -> SymmetricKey {
        try derive(myPrivate: myPrivate, theirPublic: theirPublic, salt: pairingID, info: bluetoothOuterInfo)
    }

    /// The key that wraps the master key inside one envelope. The salt is
    /// the envelope's own.
    static func envelopeKey(myPrivate: Data, theirPublic: Data, salt: Data) throws -> SymmetricKey {
        try derive(myPrivate: myPrivate, theirPublic: theirPublic, salt: salt, info: envelopeInfo)
    }

    /// The key that seals the device descriptions at the end of pairing.
    /// The transcript stands in for the salt, so the key belongs to this one
    /// handshake.
    static func pairingKey(myPrivate: Data, theirPublic: Data, transcript: Data) throws -> SymmetricKey {
        let salt = Data(SHA256.hash(data: transcript))
        return try derive(myPrivate: myPrivate, theirPublic: theirPublic, salt: salt, info: pairingInfo)
    }

    /// The key that authenticates one pairing handshake: HKDF-SHA256 over
    /// the CPace shared point, with the whole transcript as salt and a fixed
    /// label as info. The two confirmation tags are HMACs under it.
    static func pairingSessionKey(sharedPoint: Data, transcript: Data) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: sharedPoint),
                               salt: transcript,
                               info: pairingSessionInfo,
                               outputByteCount: 32)
    }

    // MARK: - Fingerprint

    /// Twenty digits both devices compute from the same two public keys.
    /// Sixty-four bits: forging a key whose digits match a chosen set costs
    /// about 2^64 attempts.
    static func fingerprint(pairingID: Data, publicKeyA: Data, publicKeyB: Data) -> String {
        let (low, high) = publicKeyA.lexicographicallyPrecedes(publicKeyB)
            ? (publicKeyA, publicKeyB) : (publicKeyB, publicKeyA)
        var input = fingerprintInfo
        input.append(pairingID)
        input.append(low)
        input.append(high)
        let digest = SHA256.hash(data: input)
        // Folded byte by byte: a raw load would need aligned memory.
        let value = digest.prefix(8).reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        let digits = String(value)
        let padded = String(repeating: "0", count: max(0, 20 - digits.count)) + digits
        var groups: [String] = []
        var index = padded.startIndex
        while index < padded.endIndex {
            let end = padded.index(index, offsetBy: 4, limitedBy: padded.endIndex) ?? padded.endIndex
            groups.append(String(padded[index..<end]))
            index = end
        }
        return groups.joined(separator: "  ")
    }
}

// MARK: - CPace over Curve25519

/// The CPace balanced password-authenticated key exchange in its CPace255
/// suite with SHA-512, as the CPace draft (draft-irtf-cfrg-cpace)
/// specifies in sections 6, 7.1 and 7.2 and repeats in its appendix A. The
/// pairing link runs it with the PIN as the password, so nothing that
/// crosses the air is a function of the PIN alone: each point sent is a
/// fresh random scalar times a generator that only a PIN holder can
/// compute. For every candidate PIN there is a scalar that would give the
/// same point.
///
/// Scalar multiplication is CryptoKit's X25519. Handing
/// `sharedSecretFromKeyAgreement` the generator as the "public key" gives
/// this side's point, and handing it the other side's point gives the
/// shared point. The map from the hashed password to the generator is
/// `Field25519.elligator2`.
nonisolated enum CPace255 {

    /// The draft's domain separation identifier for this suite.
    static let dsi = Data("CPace255".utf8)
    /// SHA-512 takes 128-byte input blocks. The generator string pads the
    /// password out to the first block, so its length does not show in the
    /// time the hash takes.
    static let hashBlockBytes = 128
    static let fieldBytes = 32
    /// The neutral element, which is what X25519 returns for a low-order
    /// point. A shared point that equals it is refused.
    static let neutral = Data(repeating: 0, count: 32)
    /// The cause the pairing link names when the other side's point is
    /// refused, written once beside the gate that raises it.
    static let lowOrderRefusal = "The other device\u{2019}s reply failed a safety check"

    /// prepend_len of the draft's appendix A.1: the string with its length
    /// in front, LEB128 encoded.
    static func prependLen(_ string: Data) -> Data {
        var out = Data()
        var length = string.count
        while length >= 128 {
            out.append(UInt8(length & 0x7F) | 0x80)
            length >>= 7
        }
        out.append(UInt8(length))
        out.append(string)
        return out
    }

    /// lv_cat of the draft's appendix A.1: every string with its length in
    /// front, concatenated.
    static func lvCat(_ parts: [Data]) -> Data {
        parts.reduce(into: Data()) { $0.append(prependLen($1)) }
    }

    /// generator_string of the draft's section 7.1 and appendix A.2.
    static func generatorString(prs: Data, ci: Data, sid: Data) -> Data {
        let zeroPad = max(0, hashBlockBytes - 1 - prependLen(prs).count - prependLen(dsi).count)
        return lvCat([dsi, prs, Data(repeating: 0, count: zeroPad), ci, sid])
    }

    /// decodeUCoordinate of RFC 7748, repeated in the draft's appendix A.4:
    /// the top bit of the last byte is not part of a 255-bit coordinate.
    static func decodeUCoordinate(_ bytes: Data) -> Field25519.Element? {
        guard bytes.count == fieldBytes else { return nil }
        var masked = bytes
        masked[masked.index(before: masked.endIndex)] &= 0x7F
        return Field25519.Element(littleEndian: masked)
    }

    /// calculate_generator of the draft's section 7.2: hash the generator
    /// string to 32 bytes, read them as a u coordinate and map that field
    /// element onto the curve. The result is the u coordinate of the
    /// generator, encoded as X25519 expects it. Nil only if the hash did
    /// not give 32 bytes, which the caller treats as a refusal to pair.
    static func generator(prs: Data, ci: Data, sid: Data) -> Data? {
        let hashed = Data(SHA512.hash(data: generatorString(prs: prs, ci: ci, sid: sid)).prefix(fieldBytes))
        guard let u = decodeUCoordinate(hashed) else { return nil }
        return Field25519.elligator2(u).s.littleEndian
    }

    /// scalar_mult_vfy of the draft's section 7.2: the scalar times the
    /// point, refused when the result is the neutral element, which is what
    /// a low-order point produces. The generator, a received point and any
    /// other thirty-two bytes load the same way, since X25519 takes every
    /// string as a u coordinate. A refusal by CryptoKit is taken as the
    /// neutral element too, so the guarantee rests on this check alone.
    static func multiply(_ scalar: Curve25519.KeyAgreement.PrivateKey, times point: Data) throws -> Data {
        let base: Curve25519.KeyAgreement.PublicKey
        do {
            base = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: point)
        } catch {
            throw TrustedDeviceError.keyMalformed
        }
        let product: Data
        do {
            product = try scalar.sharedSecretFromKeyAgreement(with: base).withUnsafeBytes { Data($0) }
        } catch {
            throw TrustedDeviceError.lowOrderPoint
        }
        guard product != neutral else { throw TrustedDeviceError.lowOrderPoint }
        return product
    }

    // MARK: - Self-test

    /// The CPace draft's own vector from its appendix B.1: the generator for
    /// the password "Password" with the draft's channel identifier and
    /// session id, the initiator's point for the draft's scalar, and the
    /// all-zero low-order point from B.1.10. The constants were extracted
    /// from the draft by the same script that feeds
    /// StressTests/PairingVectors.swift, which also runs the self-test.
    private enum DraftVector {
        static let prs = Data("Password".utf8)
        static let ci = Data(hex: "6f630b425f726573706f6e6465720b415f696e69746961746f72")
        static let sid = Data(hex: "7e4b4791d6a8ef019b936c79fb7f2c57")
        static let generator = Data(hex: "64e8099e3ea682cfdc5cb665c057ebb514d06bf23ebc9f743b51b82242327074")
        static let ya = Data(hex: "21b4f4bd9e64ed355c3eb676a28ebedaf6d8f17bdc365995b319097153044080")
        static let Ya = Data(hex: "1b02dad6dbd29a07b6d28c9e04cb2f184f0734350e32bb7e62ff9dbcfdb63d15")
        static let lowOrder = Data(hex: "0000000000000000000000000000000000000000000000000000000000000000")
    }

    /// The draft's vector, evaluated on this device through Field25519 and
    /// CryptoKit. The link runs this before the first pairing after each
    /// launch and refuses to pair when it does not match, so arithmetic
    /// that has gone wrong on some chip never derives a key.
    static func selfTest() -> Bool {
        guard let ci = DraftVector.ci, let sid = DraftVector.sid,
              let expectedGenerator = DraftVector.generator,
              let ya = DraftVector.ya, let expectedYa = DraftVector.Ya,
              let lowOrder = DraftVector.lowOrder else { return false }
        guard let generator = generator(prs: DraftVector.prs, ci: ci, sid: sid),
              generator == expectedGenerator else { return false }
        guard let scalar = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: ya),
              let point = try? multiply(scalar, times: generator), point == expectedYa else { return false }
        // A low-order point must be refused, whatever CryptoKit does with it.
        if (try? multiply(scalar, times: lowOrder)) != nil { return false }
        return true
    }

    #if DEBUG
    /// Reports, on the device this runs on, whether CryptoKit loads the map's
    /// output and a received point, whether the draft's scalar times the
    /// generator gives the draft's point, and what CryptoKit itself does with
    /// an all-zero result. The pairing link writes it to the debug log beside
    /// the self-test's verdict.
    static func probeReport() -> String {
        guard let ci = DraftVector.ci, let sid = DraftVector.sid,
              let expectedGenerator = DraftVector.generator,
              let ya = DraftVector.ya, let expectedYa = DraftVector.Ya,
              let lowOrder = DraftVector.lowOrder,
              let generator = generator(prs: DraftVector.prs, ci: ci, sid: sid),
              let scalar = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: ya) else {
            return "probe could not start"
        }
        var lines: [String] = []
        lines.append("generator matches draft: \(generator == expectedGenerator)")
        lines.append("PublicKey(rawRepresentation:) loads the map's output: \((try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: generator)) != nil)")
        lines.append("PublicKey(rawRepresentation:) loads a received point: \((try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: expectedYa)) != nil)")
        lines.append("Ya = X25519(ya, g) matches draft: \((try? multiply(scalar, times: generator)) == expectedYa)")
        if let zeroPoint = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: lowOrder) {
            do {
                let raw = try scalar.sharedSecretFromKeyAgreement(with: zeroPoint).withUnsafeBytes { Data($0) }
                lines.append("all-zero point: CryptoKit returned \(raw == neutral ? "all zeros" : "a non-zero value") without throwing")
            } catch {
                lines.append("all-zero point: CryptoKit threw \(error)")
            }
        } else {
            lines.append("all-zero point: PublicKey(rawRepresentation:) refused to load it")
        }
        lines.append("scalar_mult_vfy refuses the all-zero point: \((try? multiply(scalar, times: lowOrder)) == nil)")
        return lines.joined(separator: "\n")
    }
    #endif
}

private extension Data {
    /// Hex to bytes, nil for anything that is not an even run of hex digits.
    /// `nonisolated`, since the vectors above are read wherever the
    /// self-test runs.
    nonisolated init?(hex: String) {
        guard hex.count % 2 == 0, hex.allSatisfy(\.isHexDigit) else { return nil }
        var out = Data(capacity: hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
            out.append(byte)
            index = next
        }
        self = out
    }
}
