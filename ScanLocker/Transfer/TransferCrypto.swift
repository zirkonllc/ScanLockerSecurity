import Combine
import CommonCrypto
import CryptoKit
import Darwin
import Foundation
import Network
import Security

nonisolated enum VaultPIN {
    static func deriveRaw(_ pin: String, salt: Data) -> Data? {
        var derived = Data(count: 32)
        var status: Int32 = -1
        pin.withCString { cstr in
            let pwLen = strlen(cstr)
            status = derived.withUnsafeMutableBytes { out in
                salt.withUnsafeBytes { saltBytes in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        cstr,
                        pwLen,
                        saltBytes.bindMemory(to: UInt8.self).baseAddress,
                        salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        120_000,
                        out.bindMemory(to: UInt8.self).baseAddress,
                        32
                    )
                }
            }
        }
        guard status == kCCSuccess else { return nil }
        return derived
    }

    static func derive(_ pin: String, salt: Data) throws -> SymmetricKey {
        guard let raw = deriveRaw(pin, salt: salt) else {
            throw EncryptedVaultStorage.StorageError.sealFailed
        }
        return SymmetricKey(data: raw)
    }

    static func randomCode() -> String {
        String(format: "%06d", Int.random(in: 0...999_999))
    }
}

nonisolated enum TransferCrypto {
    static let saltLength = 16
    static let challengeLength = 32
    static let keyLength = 32
    static let tagLength = 32
    static let kemKeyLength = 1184
    static let kemCiphertextLength = 1088
    static let hello1BodyLength = tagLength + saltLength + challengeLength + keyLength + kemKeyLength
    static let hello2BodyLength = keyLength + kemCiphertextLength + tagLength
    private static let info = Data("scanlocker.transfer.v5".utf8)

    static func random(_ count: Int) -> Data? {
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes { buffer -> Int32 in
            guard let base = buffer.baseAddress else { return errSecParam }
            return SecRandomCopyBytes(kSecRandomDefault, count, base)
        }
        return status == errSecSuccess ? data : nil
    }

    private static func transcript(
        _ label: String, salt: Data, challenge: Data, senderPub: Data, senderKEM: Data,
        receiverPub: Data, kemCiphertext: Data
    ) -> Data {
        Data(label.utf8) + salt + challenge + senderPub + senderKEM + receiverPub + kemCiphertext
    }

    private static let helloLabel = "hello5"

    static func blindedPairingTag(
        channelKey: SymmetricKey, salt: Data, challenge: Data, senderPub: Data, senderKEM: Data
    ) -> Data {
        Data(HMAC<SHA256>.authenticationCode(
            for: transcript("blind5", salt: salt, challenge: challenge,
                            senderPub: senderPub, senderKEM: senderKEM,
                            receiverPub: Data(), kemCiphertext: Data()),
            using: channelKey
        ))
    }

    static func validBlindedPairingTag(
        _ tag: Data, channelKey: SymmetricKey, salt: Data,
        challenge: Data, senderPub: Data, senderKEM: Data
    ) -> Bool {
        HMAC<SHA256>.isValidAuthenticationCode(
            tag,
            authenticating: transcript("blind5", salt: salt, challenge: challenge,
                                       senderPub: senderPub, senderKEM: senderKEM,
                                       receiverPub: Data(), kemCiphertext: Data()),
            using: channelKey
        )
    }

    static func responderTag(
        channelKey: SymmetricKey, salt: Data, challenge: Data, senderPub: Data, senderKEM: Data,
        receiverPub: Data, kemCiphertext: Data
    ) -> Data {
        Data(HMAC<SHA256>.authenticationCode(
            for: transcript(helloLabel, salt: salt, challenge: challenge,
                            senderPub: senderPub, senderKEM: senderKEM,
                            receiverPub: receiverPub, kemCiphertext: kemCiphertext),
            using: channelKey
        ))
    }

    static func validResponderTag(
        _ tag: Data, channelKey: SymmetricKey, salt: Data, challenge: Data,
        senderPub: Data, senderKEM: Data, receiverPub: Data, kemCiphertext: Data
    ) -> Bool {
        HMAC<SHA256>.isValidAuthenticationCode(
            tag,
            authenticating: transcript(helloLabel, salt: salt, challenge: challenge,
                                       senderPub: senderPub, senderKEM: senderKEM,
                                       receiverPub: receiverPub, kemCiphertext: kemCiphertext),
            using: channelKey
        )
    }

    static func confirmTag(
        channelKey: SymmetricKey, salt: Data, challenge: Data, senderPub: Data, senderKEM: Data,
        receiverPub: Data, kemCiphertext: Data
    ) -> Data {
        Data(HMAC<SHA256>.authenticationCode(
            for: transcript("confirm5", salt: salt, challenge: challenge,
                            senderPub: senderPub, senderKEM: senderKEM,
                            receiverPub: receiverPub, kemCiphertext: kemCiphertext),
            using: channelKey
        ))
    }

    static func validConfirmTag(
        _ tag: Data, channelKey: SymmetricKey, salt: Data, challenge: Data,
        senderPub: Data, senderKEM: Data, receiverPub: Data, kemCiphertext: Data
    ) -> Bool {
        HMAC<SHA256>.isValidAuthenticationCode(
            tag,
            authenticating: transcript("confirm5", salt: salt, challenge: challenge,
                                       senderPub: senderPub, senderKEM: senderKEM,
                                       receiverPub: receiverPub, kemCiphertext: kemCiphertext),
            using: channelKey
        )
    }

    static func sessionKey(
        myPrivate: Curve25519.KeyAgreement.PrivateKey,
        peerPublicRaw: Data,
        kemSecret: SymmetricKey,
        salt: Data,
        challenge: Data
    ) throws -> SymmetricKey {
        let peer = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerPublicRaw)
        let shared = try myPrivate.sharedSecretFromKeyAgreement(with: peer)
        var material = shared.withUnsafeBytes { Data($0) }
        kemSecret.withUnsafeBytes { material.append(contentsOf: $0) }
        defer { material.resetBytes(in: 0..<material.count) }
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: material), salt: salt,
            info: info + challenge, outputByteCount: 32
        )
    }

    static func seal(_ data: Data, key: SymmetricKey) throws -> Data {
        guard let combined = try AES.GCM.seal(data, using: key).combined else {
            throw EncryptedVaultStorage.StorageError.sealFailed
        }
        return combined
    }

    static func open(_ data: Data, key: SymmetricKey) throws -> Data {
        try AES.GCM.open(AES.GCM.SealedBox(combined: data), using: key)
    }
}
