import CryptoKit
import Foundation

nonisolated struct TrustedPairingCard: Equatable, Sendable {
    static let prefix = "SLPAIR1."
    static let halfLength = 8
    static let textCeiling = 2_048

    private static let version: UInt8 = 0x01
    private static let fieldByteCeiling = 120
    private static let checkInfo = Data("ScanLocker pairing card check v2".utf8)
    static let checkBytesPerCard = 12

    let publicKey: Data
    let half: Data
    let description: DeviceDescription

    init?(publicKey: Data, half: Data, description: DeviceDescription) {
        guard TrustedDeviceCrypto.isValidPublicKey(publicKey), half.count == Self.halfLength else { return nil }
        self.publicKey = publicKey
        self.half = half
        self.description = description.clamped()
    }

    var text: String {
        var payload = Data([Self.version])
        payload.append(publicKey)
        payload.append(half)
        for field in [description.name, description.family, description.machine, description.systemVersion] {
            let bytes = Self.fieldBytes(field)
            payload.append(UInt8(bytes.count))
            payload.append(bytes)
        }
        return Self.prefix + Self.base64URL(payload)
    }

    init?(text: String) {
        guard text.count <= Self.textCeiling, let start = text.range(of: Self.prefix) else { return nil }
        let allowed = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        let body = String(text[start.upperBound...].prefix { allowed.contains($0) })
        guard let payload = Self.data(base64URL: body) else { return nil }
        var offset = payload.startIndex
        func take(_ count: Int) -> Data? {
            guard count >= 0, payload.distance(from: offset, to: payload.endIndex) >= count else { return nil }
            let slice = Data(payload[offset..<offset + count])
            offset += count
            return slice
        }
        func string() -> String? {
            guard let length = take(1)?.first, let bytes = take(Int(length)) else { return nil }
            return String(decoding: bytes, as: UTF8.self)
        }
        guard take(1)?.first == Self.version,
              let key = take(TrustedDeviceCrypto.publicKeyLength),
              let half = take(Self.halfLength),
              let name = string(), let family = string(), let machine = string(), let system = string(),
              offset == payload.endIndex else { return nil }
        self.init(publicKey: key, half: half,
                  description: DeviceDescription(name: name, family: family, machine: machine, systemVersion: system))
    }

    static func pairingID(mine: TrustedPairingCard, theirs: TrustedPairingCard) -> Data {
        let (low, high) = ordered(mine, theirs)
        return low.half + high.half
    }

    static func check(mine: TrustedPairingCard, theirs: TrustedPairingCard) -> String {
        let (low, high) = ordered(mine, theirs)
        return [low, high].map { grouped(commitment($0)) }.joined(separator: "\n")
    }

    private static func commitment(_ card: TrustedPairingCard) -> String {
        var input = checkInfo
        input.append(card.publicKey)
        input.append(card.half)
        return SHA256.hash(data: input).prefix(checkBytesPerCard).map { String(format: "%02X", $0) }.joined()
    }

    private static func grouped(_ hex: String) -> String {
        stride(from: 0, to: hex.count, by: 4).map { start in
            let from = hex.index(hex.startIndex, offsetBy: start)
            let to = hex.index(from, offsetBy: min(4, hex.count - start))
            return String(hex[from..<to])
        }.joined(separator: " ")
    }

    private static func ordered(_ a: TrustedPairingCard, _ b: TrustedPairingCard) -> (TrustedPairingCard, TrustedPairingCard) {
        a.publicKey.lexicographicallyPrecedes(b.publicKey) ? (a, b) : (b, a)
    }

    private static func fieldBytes(_ field: String) -> Data {
        var out = Data()
        for character in field {
            let next = Data(String(character).utf8)
            guard out.count + next.count <= fieldByteCeiling else { break }
            out.append(next)
        }
        return out
    }

    private static func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private static func data(base64URL text: String) -> Data? {
        var plain = text
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = plain.count % 4
        if remainder == 1 { return nil }
        if remainder > 0 { plain += String(repeating: "=", count: 4 - remainder) }
        return Data(base64Encoded: plain)
    }
}
