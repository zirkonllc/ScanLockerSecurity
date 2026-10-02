import CryptoKit
import Foundation

enum TransferResume {
    static let resumeType: UInt8 = 0x0A
    static let queryType: UInt8 = 0x0B
    static let noSessionType: UInt8 = 0x0C
    static let bodyLength = 4 + tagLength
    static let queryBodyLength = tagLength
    static let noSessionBodyLength = 1

    private static let tagLength = 32
    private static let label = "scanlocker.transfer.resume.v1"

    static func message(index: Int, sessionKey: SymmetricKey) -> Data {
        let counted = UInt32(clamping: max(0, index))
        let tag = HMAC<SHA256>.authenticationCode(for: authenticated(counted), using: key(sessionKey))
        return Data([resumeType]) + wire(counted) + Data(tag)
    }

    static func index(body: Data, sessionKey: SymmetricKey) -> Int? {
        let flat = Data(body)
        guard flat.count == bodyLength else { return nil }
        let counted = flat.prefix(4).reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
        guard HMAC<SHA256>.isValidAuthenticationCode(flat.suffix(tagLength), authenticating: authenticated(counted),
                                                      using: key(sessionKey)) else { return nil }
        return Int(counted)
    }

    static func query(sessionKey: SymmetricKey) -> Data {
        Data([queryType]) + Data(HMAC<SHA256>.authenticationCode(for: Data(queryLabel.utf8), using: key(sessionKey)))
    }

    static func validQuery(body: Data, sessionKey: SymmetricKey) -> Bool {
        let flat = Data(body)
        guard flat.count == queryBodyLength else { return false }
        return HMAC<SHA256>.isValidAuthenticationCode(flat, authenticating: Data(queryLabel.utf8), using: key(sessionKey))
    }

    static var noSession: Data { Data([noSessionType, 0]) }

    private static let queryLabel = "scanlocker.transfer.resume.query.v1"

    private static func key(_ sessionKey: SymmetricKey) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: sessionKey, info: Data(label.utf8), outputByteCount: 32)
    }

    private static func wire(_ value: UInt32) -> Data {
        var out = Data()
        withUnsafeBytes(of: value.bigEndian) { out.append(contentsOf: $0) }
        return out
    }

    private static func authenticated(_ value: UInt32) -> Data {
        Data(label.utf8) + wire(value)
    }
}
