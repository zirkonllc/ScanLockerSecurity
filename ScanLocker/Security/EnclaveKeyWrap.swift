import CryptoKit
import Foundation
import Security

enum EnclaveKeyWrap {
    struct Slot {
        let service: String
        let wrappedAccount: String
        let rawAccount: String
        let privateKeyAccount: String
        let label: String
    }

    enum Failure: Error {
        case keyUnavailable
    }

    struct Loaded {
        let key: SymmetricKey
        let wrappedByEnclave: Bool
    }

    static var isAvailable: Bool { SecureEnclave.isAvailable }

    static func loadOrCreate(in slot: Slot,
                             adopting: () -> SymmetricKey? = { nil },
                             mintRefusedWhen: () -> Bool = { false }) throws -> Loaded {
        let wrappedRead = KeychainGeneric.read(service: slot.service, account: slot.wrappedAccount)
        if case .found(let wrapped) = wrappedRead, let raw = unwrap(wrapped, slot: slot) {
            return Loaded(key: SymmetricKey(data: raw), wrappedByEnclave: true)
        }
        let rawRead = KeychainGeneric.read(service: slot.service, account: slot.rawAccount)
        if case .found(let raw) = rawRead {
            return Loaded(key: SymmetricKey(data: raw), wrappedByEnclave: false)
        }
        guard case .notFound = wrappedRead, case .notFound = rawRead else {
            VaultLog.failure(.keychainWriteFailed,
                             detail: "\(slot.wrappedAccount) present or unreadable; not replaced")
            throw Failure.keyUnavailable
        }
        guard mintRefusedWhen() == false else {
            VaultLog.failure(.keychainWriteFailed,
                             detail: "\(slot.wrappedAccount) absent while sealed records name another key")
            throw Failure.keyUnavailable
        }
        let key = adopting() ?? SymmetricKey(size: .bits256)
        return try store(raw: key.withUnsafeBytes { Data($0) }, in: slot)
    }

    static func store(raw: Data, in slot: Slot) throws -> Loaded {
        if isAvailable, let wrapped = try wrap(raw, slot: slot) {
            let added = KeychainGeneric.add(service: slot.service, account: slot.wrappedAccount, data: wrapped)
            if added == .stored,
               let stored = KeychainGeneric.get(service: slot.service, account: slot.wrappedAccount),
               let roundTrip = unwrap(stored, slot: slot),
               roundTrip == raw {
                return Loaded(key: SymmetricKey(data: raw), wrappedByEnclave: true)
            }
            let answered = keychainAnswers(for: slot)
            if added == .stored {
                KeychainGeneric.delete(service: slot.service, account: slot.wrappedAccount)
            }
            if added != .duplicate {
                KeychainGeneric.delete(service: slot.service, account: slot.privateKeyAccount)
            }
            guard added == .stored, answered else {
                VaultLog.failure(.keychainWriteFailed,
                                 detail: "\(slot.wrappedAccount) refused or unanswered; no raw key stored")
                throw Failure.keyUnavailable
            }
        }
        guard KeychainGeneric.addOnly(service: slot.service, account: slot.rawAccount, data: raw) else {
            throw Failure.keyUnavailable
        }
        guard let stored = KeychainGeneric.get(service: slot.service, account: slot.rawAccount),
              stored == raw else {
            KeychainGeneric.delete(service: slot.service, account: slot.rawAccount)
            throw Failure.keyUnavailable
        }
        return Loaded(key: SymmetricKey(data: raw), wrappedByEnclave: false)
    }

    private static func keychainAnswers(for slot: Slot) -> Bool {
        for account in [slot.wrappedAccount, slot.privateKeyAccount] {
            if case .unavailable = KeychainGeneric.read(service: slot.service, account: account) {
                return false
            }
        }
        return true
    }

    private static func wrap(_ aesRaw: Data, slot: Slot) throws -> Data? {
        var added = false
        do {
            let se = try SecureEnclave.P256.KeyAgreement.PrivateKey()
            let ephemeral = P256.KeyAgreement.PrivateKey()
            let secret = try se.sharedSecretFromKeyAgreement(with: ephemeral.publicKey)
            let wrapKey = secret.hkdfDerivedSymmetricKey(
                using: SHA256.self,
                salt: Data(slot.label.utf8),
                sharedInfo: Data(),
                outputByteCount: 32
            )
            let box = try AES.GCM.seal(aesRaw, using: wrapKey)
            guard let combined = box.combined else { return nil }
            try addEnclaveRecord(se.dataRepresentation, slot: slot)
            added = true
            return try JSONEncoder().encode(Pack(ephPub: ephemeral.publicKey.x963Representation, box: combined))
        } catch let failure as Failure {
            throw failure
        } catch {
            if added {
                KeychainGeneric.delete(service: slot.service, account: slot.privateKeyAccount)
            }
            return nil
        }
    }

    private static func addEnclaveRecord(_ data: Data, slot: Slot) throws {
        var answer = KeychainGeneric.add(service: slot.service, account: slot.privateKeyAccount, data: data)
        if answer == .duplicate,
           case .notFound = KeychainGeneric.read(service: slot.service, account: slot.wrappedAccount) {
            KeychainGeneric.delete(service: slot.service, account: slot.privateKeyAccount)
            answer = KeychainGeneric.add(service: slot.service, account: slot.privateKeyAccount, data: data)
        }
        guard answer == .stored else { throw Failure.keyUnavailable }
        guard KeychainGeneric.get(service: slot.service, account: slot.privateKeyAccount) != nil else {
            KeychainGeneric.delete(service: slot.service, account: slot.privateKeyAccount)
            throw Failure.keyUnavailable
        }
    }

    private static func unwrap(_ wrapped: Data, slot: Slot) -> Data? {
        do {
            guard let seData = KeychainGeneric.get(service: slot.service, account: slot.privateKeyAccount) else {
                return nil
            }
            let pack = try JSONDecoder().decode(Pack.self, from: wrapped)
            let se = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: seData)
            let ephPub = try P256.KeyAgreement.PublicKey(x963Representation: pack.ephPub)
            let secret = try se.sharedSecretFromKeyAgreement(with: ephPub)
            let wrapKey = secret.hkdfDerivedSymmetricKey(
                using: SHA256.self,
                salt: Data(slot.label.utf8),
                sharedInfo: Data(),
                outputByteCount: 32
            )
            let box = try AES.GCM.SealedBox(combined: pack.box)
            return try AES.GCM.open(box, using: wrapKey)
        } catch {
            return nil
        }
    }

    private struct Pack: Codable {
        var ephPub: Data
        var box: Data
    }
}

enum KeychainGeneric {
    enum Read {
        case found(Data)
        case notFound
        case unavailable
    }

    static func read(service: String, account: String) -> Read {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            guard let data = item as? Data else { return .unavailable }
            return .found(data)
        case errSecItemNotFound:
            return .notFound
        default:
            return .unavailable
        }
    }

    static func get(service: String, account: String) -> Data? {
        if case .found(let data) = read(service: service, account: account) { return data }
        return nil
    }

    private static func addAttributes(service: String, account: String, data: Data) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecAttrSynchronizable as String: false
        ]
    }

    @discardableResult
    static func addOnly(service: String, account: String, data: Data) -> Bool {
        add(service: service, account: account, data: data) == .stored
    }

    enum Added {
        case stored
        case duplicate
        case refused
    }

    static func add(service: String, account: String, data: Data) -> Added {
        switch SecItemAdd(addAttributes(service: service, account: account, data: data) as CFDictionary, nil) {
        case errSecSuccess: return .stored
        case errSecDuplicateItem: return .duplicate
        default: return .refused
        }
    }

    static func set(service: String, account: String, data: Data) -> Bool {
        let status = SecItemAdd(addAttributes(service: service, account: account, data: data) as CFDictionary, nil)
        if status == errSecSuccess { return true }
        guard status == errSecDuplicateItem else { return false }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        let update: [String: Any] = [kSecValueData as String: data]
        return SecItemUpdate(query as CFDictionary, update as CFDictionary) == errSecSuccess
    }

    @discardableResult
    static func delete(service: String, account: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        let status = SecItemDelete(query as CFDictionary)
        if status != errSecSuccess && status != errSecItemNotFound {
            VaultLog.failure(.keychainWriteFailed, detail: "delete \(account) status \(status)")
            return false
        }
        return true
    }

    static func deleteService(_ service: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service
        ]
        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
    }
}
