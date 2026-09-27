import CryptoKit
import Foundation
import Security

nonisolated enum TrustedDeviceError: LocalizedError, Equatable {
    case randomnessUnavailable
    case keyMalformed
    case storeWriteFailed
    case recordsSuspect
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

    static func randomBytes(_ count: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        guard status == errSecSuccess else { throw TrustedDeviceError.randomnessUnavailable }
        return Data(bytes)
    }

    struct KeyPair: Equatable {
        let privateKey: Data
        let publicKey: Data

        static func generate() -> KeyPair {
            let key = Curve25519.KeyAgreement.PrivateKey()
            return KeyPair(privateKey: key.rawRepresentation,
                           publicKey: key.publicKey.rawRepresentation)
        }
    }

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

    static func transferKey(myPrivate: Data, theirPublic: Data, salt: Data) throws -> SymmetricKey {
        try derive(myPrivate: myPrivate, theirPublic: theirPublic, salt: salt, info: transferInfo)
    }

    static func bluetoothOuterKey(myPrivate: Data, theirPublic: Data, pairingID: Data) throws -> SymmetricKey {
        try derive(myPrivate: myPrivate, theirPublic: theirPublic, salt: pairingID, info: bluetoothOuterInfo)
    }

    static func envelopeKey(myPrivate: Data, theirPublic: Data, salt: Data) throws -> SymmetricKey {
        try derive(myPrivate: myPrivate, theirPublic: theirPublic, salt: salt, info: envelopeInfo)
    }

    static func pairingKey(myPrivate: Data, theirPublic: Data, transcript: Data) throws -> SymmetricKey {
        let salt = Data(SHA256.hash(data: transcript))
        return try derive(myPrivate: myPrivate, theirPublic: theirPublic, salt: salt, info: pairingInfo)
    }

    static func pairingSessionKey(sharedPoint: Data, transcript: Data) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: sharedPoint),
                               salt: transcript,
                               info: pairingSessionInfo,
                               outputByteCount: 32)
    }

    static func fingerprint(pairingID: Data, publicKeyA: Data, publicKeyB: Data) -> String {
        let (low, high) = publicKeyA.lexicographicallyPrecedes(publicKeyB)
            ? (publicKeyA, publicKeyB) : (publicKeyB, publicKeyA)
        var input = fingerprintInfo
        input.append(pairingID)
        input.append(low)
        input.append(high)
        let digest = SHA256.hash(data: input)
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

nonisolated enum CPace255 {
    static let dsi = Data("CPace255".utf8)
    static let hashBlockBytes = 128
    static let fieldBytes = 32
    static let neutral = Data(repeating: 0, count: 32)
    static let lowOrderRefusal = "The other device\u{2019}s reply failed a safety check"

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

    static func lvCat(_ parts: [Data]) -> Data {
        parts.reduce(into: Data()) { $0.append(prependLen($1)) }
    }

    static func generatorString(prs: Data, ci: Data, sid: Data) -> Data {
        let zeroPad = max(0, hashBlockBytes - 1 - prependLen(prs).count - prependLen(dsi).count)
        return lvCat([dsi, prs, Data(repeating: 0, count: zeroPad), ci, sid])
    }

    static func decodeUCoordinate(_ bytes: Data) -> Field25519.Element? {
        guard bytes.count == fieldBytes else { return nil }
        var masked = bytes
        masked[masked.index(before: masked.endIndex)] &= 0x7F
        return Field25519.Element(littleEndian: masked)
    }

    static func generator(prs: Data, ci: Data, sid: Data) -> Data? {
        let hashed = Data(SHA512.hash(data: generatorString(prs: prs, ci: ci, sid: sid)).prefix(fieldBytes))
        guard let u = decodeUCoordinate(hashed) else { return nil }
        return Field25519.elligator2(u).s.littleEndian
    }

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

    private enum DraftVector {
        static let prs = Data("Password".utf8)
        static let ci = Data(hex: "6f630b425f726573706f6e6465720b415f696e69746961746f72")
        static let sid = Data(hex: "7e4b4791d6a8ef019b936c79fb7f2c57")
        static let generator = Data(hex: "64e8099e3ea682cfdc5cb665c057ebb514d06bf23ebc9f743b51b82242327074")
        static let ya = Data(hex: "21b4f4bd9e64ed355c3eb676a28ebedaf6d8f17bdc365995b319097153044080")
        static let Ya = Data(hex: "1b02dad6dbd29a07b6d28c9e04cb2f184f0734350e32bb7e62ff9dbcfdb63d15")
        static let lowOrder = Data(hex: "0000000000000000000000000000000000000000000000000000000000000000")
    }

    static func selfTest() -> Bool {
        guard let ci = DraftVector.ci, let sid = DraftVector.sid,
              let expectedGenerator = DraftVector.generator,
              let ya = DraftVector.ya, let expectedYa = DraftVector.Ya,
              let lowOrder = DraftVector.lowOrder else { return false }
        guard let generator = generator(prs: DraftVector.prs, ci: ci, sid: sid),
              generator == expectedGenerator else { return false }
        guard let scalar = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: ya),
              let point = try? multiply(scalar, times: generator), point == expectedYa else { return false }
        if (try? multiply(scalar, times: lowOrder)) != nil { return false }
        return true
    }

    #if DEBUG
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
