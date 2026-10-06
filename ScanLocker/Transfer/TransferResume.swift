import CryptoKit
import Foundation

enum TransferResume {
    static let resumeType: UInt8 = 0x0A
    static let queryType: UInt8 = 0x0B
    static let noSessionType: UInt8 = 0x0C
    static let bodyLength = 4 + tagLength
    static let nonceLength = 16
    static let queryBodyLength = nonceLength + tagLength
    static let noSessionBodyLength = 1

    private static let tagLength = 32
    private static let label = "scanlocker.transfer.resume.v2"

    static func freshNonce() -> Data {
        SymmetricKey(size: .bits128).withUnsafeBytes { Data($0) }
    }

    static func message(index: Int, nonce: Data, sessionKey: SymmetricKey) -> Data {
        let counted = UInt32(clamping: max(0, index))
        let tag = HMAC<SHA256>.authenticationCode(for: authenticated(counted, nonce), using: key(sessionKey))
        return Data([resumeType]) + wire(counted) + Data(tag)
    }

    static func index(body: Data, nonce: Data, sessionKey: SymmetricKey) -> Int? {
        let flat = Data(body)
        guard flat.count == bodyLength, nonce.count == nonceLength else { return nil }
        let counted = flat.prefix(4).reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
        guard HMAC<SHA256>.isValidAuthenticationCode(flat.suffix(tagLength), authenticating: authenticated(counted, nonce),
                                                      using: key(sessionKey)) else { return nil }
        return Int(counted)
    }

    static func query(nonce: Data, sessionKey: SymmetricKey) -> Data {
        let tag = HMAC<SHA256>.authenticationCode(for: Data(queryLabel.utf8) + nonce, using: key(sessionKey))
        return Data([queryType]) + nonce + Data(tag)
    }

    static func nonce(inQuery body: Data, sessionKey: SymmetricKey) -> Data? {
        let flat = Data(body)
        guard flat.count == queryBodyLength else { return nil }
        let nonce = Data(flat.prefix(nonceLength))
        guard HMAC<SHA256>.isValidAuthenticationCode(flat.suffix(tagLength),
                                                      authenticating: Data(queryLabel.utf8) + nonce,
                                                      using: key(sessionKey)) else { return nil }
        return nonce
    }

    static var noSession: Data { Data([noSessionType, 0]) }

    private static let queryLabel = "scanlocker.transfer.resume.query.v2"

    private static func key(_ sessionKey: SymmetricKey) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: sessionKey, info: Data(label.utf8), outputByteCount: 32)
    }

    private static func wire(_ value: UInt32) -> Data {
        var out = Data()
        withUnsafeBytes(of: value.bigEndian) { out.append(contentsOf: $0) }
        return out
    }

    private static func authenticated(_ value: UInt32, _ nonce: Data) -> Data {
        Data(label.utf8) + wire(value) + nonce
    }
}
