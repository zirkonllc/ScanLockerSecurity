//
//  SealedEnvelope.swift
//  ScanLocker
//
//  ================= WHAT THIS FILE IS =================
//  The shape of every sealed blob this app stores: a page, a thumbnail, a
//  Locker item, a catalog, a staging manifest. One format byte, then the
//  four-byte identifier of the key the blob was sealed under, then the
//  AES-256-GCM box. The header and the blob's own name are the box's
//  authenticated data, so a blob opens only under the key its header
//  names and only under the name it was sealed with. A blob copied under
//  another name, or placed under another record, refuses.
//
//  The key identifier is the first four bytes of the SHA-256 of the key's
//  bytes. It lets a reader holding several keys know which one a blob was
//  sealed under without guessing, and it is what a copy of the vault kept
//  elsewhere carries beside each blob.
//
//  There is one format, and a blob whose format byte is not that one is
//  refused. It is never deleted and never rewritten by the reader that
//  refused it: a blob this build cannot read may be one a later build
//  wrote, and destroying it would turn a refusal into a loss.
//
//  Nothing here touches disk or the Keychain. It seals and opens bytes.
//

import CryptoKit
import Foundation

enum SealedEnvelope {

    /// The one format this build writes and the only one it reads.
    static let formatV1: UInt8 = 0x01
    static let keyIDLength = 4
    static let headerLength = 1 + keyIDLength

    /// A key's identifier: the first four bytes of the SHA-256 of its bytes.
    static func keyID(of key: SymmetricKey) -> Data {
        let digest = key.withUnsafeBytes { SHA256.hash(data: Data($0)) }
        return Data(digest.prefix(keyIDLength))
    }

    /// The same identifier as lowercase hex, which is how it is spelled
    /// wherever it has to be a string: a Keychain account, a wire field, a
    /// cloud record field. Spelled here and nowhere else.
    static func keyIDHex(of key: SymmetricKey) -> String {
        hex(keyID(of: key))
    }

    static func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    /// What the first five bytes of a sealed blob say.
    struct Header: Equatable {
        let format: UInt8
        let keyID: Data

        var bytes: Data { Data([format]) + keyID }
    }

    enum Refusal: Error {
        /// Shorter than a header and a sealed box.
        case truncated
        /// The format byte is one this build does not know.
        case unknownFormat(UInt8)
        /// The header names a key the reader does not hold.
        case keyUnknown(Data)
        /// CryptoKit produced a box with no combined form, which it does
        /// only for a nonce of the wrong length and never here.
        case sealFailed
    }

    /// Reads the header and refuses a blob whose format byte is unknown.
    static func header(of sealed: Data) throws -> Header {
        guard sealed.count >= headerLength else { throw Refusal.truncated }
        let start = sealed.startIndex
        let format = sealed[start]
        guard format == formatV1 else { throw Refusal.unknownFormat(format) }
        let keyID = Data(sealed[(start + 1) ..< (start + headerLength)])
        return Header(format: format, keyID: keyID)
    }

    /// The key identifier a blob names, or nil when the blob has no
    /// readable header. A reader with several keys asks this first.
    static func keyID(in sealed: Data) -> Data? {
        try? header(of: sealed).keyID
    }

    /// Seals `plaintext` under `key`, bound to `name`. The result is the
    /// header followed by the AES-GCM box, and the header and the name are
    /// its authenticated data.
    static func seal(_ plaintext: Data, key: SymmetricKey, name: String) throws -> Data {
        let header = Header(format: formatV1, keyID: keyID(of: key)).bytes
        let box = try AES.GCM.seal(plaintext, using: key, authenticating: header + Data(name.utf8))
        guard let combined = box.combined else { throw Refusal.sealFailed }
        return header + combined
    }

    /// Opens a blob under `key`, bound to `name`. The header's key
    /// identifier has to be this key's, and the box has to authenticate
    /// under the header and the name, or the blob refuses.
    static func open(_ sealed: Data, key: SymmetricKey, name: String) throws -> Data {
        let header = try header(of: sealed)
        guard header.keyID == keyID(of: key) else { throw Refusal.keyUnknown(header.keyID) }
        let box = try AES.GCM.SealedBox(combined: sealed.dropFirst(headerLength))
        return try AES.GCM.open(box, using: key, authenticating: header.bytes + Data(name.utf8))
    }

    /// Opens a blob under whichever of `ring` its header names. A header
    /// naming a key the ring does not hold refuses before any key is tried.
    static func open(_ sealed: Data, ring: [Data: SymmetricKey], name: String) throws -> Data {
        let header = try header(of: sealed)
        guard let key = ring[header.keyID] else { throw Refusal.keyUnknown(header.keyID) }
        return try open(sealed, key: key, name: name)
    }

    /// Seals and opens one blob under each key with a name as authenticated
    /// data, and requires the header to carry the key's identifier, the
    /// blob to refuse under another name, and every key to have an
    /// identifier of its own. Run at every launch on each of the app's
    /// keys, so a build in which any of this drifted refuses to proceed and
    /// never touches a stored file. Sends nothing and stores nothing.
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
