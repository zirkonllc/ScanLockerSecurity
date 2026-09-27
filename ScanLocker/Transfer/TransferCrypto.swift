//
//  TransferCrypto.swift
//  ScanLocker
//
//  The keys a transfer is sealed with, and the PIN the two iPhones agree on.
//

import Combine
import CommonCrypto
import CryptoKit
import Darwin
import Foundation
import Network
import Security

nonisolated enum VaultPIN {
    /// The one PBKDF2 in the app. The PIN hash and the trusted
    /// device pairing PIN both derive through here, so the algorithm, the iteration
    /// count, and the failure handling can never drift apart. A CommonCrypto
    /// status other than success returns nil, so no key is ever made from
    /// bytes the derivation never filled.
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

/// The transfer channel's cryptography, in one place. An ephemeral
/// Curve25519 agreement and an ML-KEM-768 encapsulation give every transfer
/// a fresh key that holds while either of the two holds, so a recorded
/// transfer is undecryptable afterwards, and an HMAC keyed by the channel
/// key binds both sides' handshake to one trusted device pairing. The
/// channel key is derived by `TrustedDeviceCrypto.transferKey` from the two
/// static keys the pairing made and the salt this transfer minted, so only
/// the device that holds the matching private key can produce a valid tag,
/// and nothing about the tag can be guessed offline. A tag that does not
/// verify is a device that is not the one it claims to be; the sender
/// allows five and then stops. The wait for each message is bounded
/// (LocalVaultLink.handshakeDeadline). The envelope inside is wrapped under
/// a second key from the same pairing, so the channel is one wall and the
/// envelope is another.
nonisolated enum TransferCrypto {
    static let saltLength = 16
    static let challengeLength = 32
    static let keyLength = 32
    static let tagLength = 32
    /// The ML-KEM-768 encapsulation key the sender states in HELLO1, and the
    /// ciphertext the receiver answers with in HELLO2.
    static let kemKeyLength = 1184
    static let kemCiphertextLength = 1088
    static let hello1BodyLength = tagLength + saltLength + challengeLength + keyLength + kemKeyLength
    static let hello2BodyLength = keyLength + kemCiphertextLength + tagLength
    /// v5, beside the handshake label below. The session key takes the
    /// ML-KEM shared secret after the X25519 one.
    private static let info = Data("scanlocker.transfer.v5".utf8)

    static func random(_ count: Int) -> Data? {
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes { buffer -> Int32 in
            guard let base = buffer.baseAddress else { return errSecParam }
            return SecRandomCopyBytes(kSecRandomDefault, count, base)
        }
        return status == errSecSuccess ? data : nil
    }

    /// Every tag authenticates the whole handshake transcript, so no field
    /// can be swapped or stripped without the tag failing. Every field has a
    /// fixed length, and the callers refuse any other length before a tag is
    /// read. The tags stay classical: they authenticate, and a recording
    /// cannot break authentication after the fact.
    private static func transcript(
        _ label: String, salt: Data, challenge: Data, senderPub: Data, senderKEM: Data,
        receiverPub: Data, kemCiphertext: Data
    ) -> Data {
        Data(label.utf8) + salt + challenge + senderPub + senderKEM + receiverPub + kemCiphertext
    }

    /// The handshake's label. v5, both hellos carrying an ML-KEM field: a
    /// device on an earlier wire
    /// produces a tag that does not verify, so the two refuse each other at
    /// the handshake and before any payload crosses.
    private static let helloLabel = "hello5"

    /// The opening message's blinded pairing identifier.
    ///
    /// The sender computes one, because it knows which device it is sending
    /// to. The receiver recomputes one per record it holds and matches. The
    /// value changes with every salt, challenge and ephemeral key, so a
    /// listener that copies it holds something naming no device and working
    /// in no other transfer, where the raw identifier it replaces was the
    /// stable value that links two paired devices for as long as they stay
    /// paired.
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

    /// Fresh key per transfer, bound to this handshake's salt and challenge.
    /// HKDF reads the X25519 secret followed by the ML-KEM shared secret, so
    /// the key is as strong as the stronger of the two. The joined bytes are
    /// zeroed once the key exists.
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
