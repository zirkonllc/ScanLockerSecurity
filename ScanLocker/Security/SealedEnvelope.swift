import CryptoKit
import Foundation

enum SealedEnvelope {
    static let formatV1: UInt8 = 0x01
    static let keyIDLength = 4
    static let headerLength = 1 + keyIDLength

    static func keyID(of key: SymmetricKey) -> Data {
        let digest = key.withUnsafeBytes { SHA256.hash(data: Data($0)) }
        return Data(digest.prefix(keyIDLength))
    }

    static func keyIDHex(of key: SymmetricKey) -> String {
        hex(keyID(of: key))
    }

    static func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    struct Header: Equatable {
        let format: UInt8
        let keyID: Data

        var bytes: Data { Data([format]) + keyID }
    }

    enum Refusal: Error {
        case truncated
        case unknownFormat(UInt8)
        case keyUnknown(Data)
        case sealFailed
    }

    static func header(of sealed: Data) throws -> Header {
        guard sealed.count >= headerLength else { throw Refusal.truncated }
        let start = sealed.startIndex
        let format = sealed[start]
        guard format == formatV1 else { throw Refusal.unknownFormat(format) }
        let keyID = Data(sealed[(start + 1) ..< (start + headerLength)])
        return Header(format: format, keyID: keyID)
    }

    static func keyID(in sealed: Data) -> Data? {
        try? header(of: sealed).keyID
    }

    static func seal(_ plaintext: Data, key: SymmetricKey, name: String) throws -> Data {
        let header = Header(format: formatV1, keyID: keyID(of: key)).bytes
        let box = try AES.GCM.seal(plaintext, using: key, authenticating: header + Data(name.utf8))
        guard let combined = box.combined else { throw Refusal.sealFailed }
        return header + combined
    }

    static func open(_ sealed: Data, key: SymmetricKey, name: String) throws -> Data {
        let header = try header(of: sealed)
        guard header.keyID == keyID(of: key) else { throw Refusal.keyUnknown(header.keyID) }
        let box = try AES.GCM.SealedBox(combined: sealed.dropFirst(headerLength))
        return try AES.GCM.open(box, using: key, authenticating: header.bytes + Data(name.utf8))
    }

    static func open(_ sealed: Data, ring: [Data: SymmetricKey], name: String) throws -> Data {
        let header = try header(of: sealed)
        guard let key = ring[header.keyID] else { throw Refusal.keyUnknown(header.keyID) }
        return try open(sealed, key: key, name: name)
    }

    static func selfTest(keys: [SymmetricKey]) -> Bool {
        guard keys.isEmpty == false else { return false }
        let plain = Data("scanlocker.selftest".utf8)
        let name = "self-test"
        for key in keys {
            guard let sealed = try? seal(plain, key: key, name: name),
                  let header = try? header(of: sealed),
                  header.format == formatV1,
                  header.keyID == keyID(of: key),
                  (try? open(sealed, key: key, name: name)) == plain,
                  (try? open(sealed, key: key, name: name + "x")) == nil,
                  (try? open(sealed, ring: [keyID(of: key): key], name: name)) == plain else {
                return false
            }
        }
        return Set(keys.map { keyID(of: $0) }).count == keys.count
    }
}
