//
//  EnclaveKeyWrap.swift
//  ScanLocker
//
//  ================= WHAT THIS FILE IS =================
//  The one definition of how a thirty-two-byte AES key is kept at rest
//  wrapped by the Secure Enclave, and of how such a key is minted, stored
//  and read back. The Locker's key and the two Vault keys, one per tab,
//  take the same wrap, which is defined here and nowhere else.
//
//  The wrap: a P-256 key made inside the Secure Enclave, an ephemeral P-256
//  key made for this one wrap, their agreement run through HKDF under a
//  label that names the slot, and the AES key sealed with AES-GCM under the
//  result. The Keychain holds the Enclave key's data representation, which
//  only this chip can use, and the ephemeral public key beside the sealed
//  box. The Enclave never sees the AES key.
//
//  The loss mode is the one a wrap always adds: a component whose failure
//  loses what it wraps. Every read here
//  fails closed. A record that exists and will not open, and a Keychain that
//  will not answer, both stop the caller, and a fresh key is minted only
//  when the Keychain says, explicitly, that nothing is stored under either
//  of the slot's accounts. Minting over an unreadable record would orphan
//  every blob sealed under it while the app looked healthy.
//
//  Every item is WhenUnlockedThisDeviceOnly and never synchronised. A key
//  kept through this file never leaves the phone in any form.
//

import CryptoKit
import Foundation
import Security

enum EnclaveKeyWrap {

    /// Where one wrapped key lives: the Keychain service, the account that
    /// holds the wrapped key, the account that holds the raw key on a device
    /// with no Enclave, the account that holds the Enclave key, and the
    /// label the wrap's derivation is salted with. Two slots in one service
    /// hold two Enclave keys, so removing one slot's key never touches the
    /// other's.
    struct Slot {
        let service: String
        let wrappedAccount: String
        let rawAccount: String
        let privateKeyAccount: String
        let label: String
    }

    enum Failure: Error {
        /// The Keychain holds a record that will not open, or would not
        /// answer. Nothing was minted and nothing was replaced.
        case keyUnavailable
    }

    /// What a load found: the key, and whether the Enclave wraps it.
    struct Loaded {
        let key: SymmetricKey
        let wrappedByEnclave: Bool
    }

    static var isAvailable: Bool { SecureEnclave.isAvailable }

    /// The key in this slot, read back, or freshly minted and stored when
    /// the Keychain says explicitly that nothing is stored there. `adopting`
    /// is asked once before a key is minted, and the bytes it answers with
    /// are stored as the slot's key; a slot whose key never leaves the
    /// phone passes nothing.
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
        // Only two explicit "nothing stored" answers permit a new key.
        // Anything else, including the locked-device answer iOS gives during
        // app prewarming or a background launch, fails closed.
        guard case .notFound = wrappedRead, case .notFound = rawRead else {
            VaultLog.failure(.keychainWriteFailed,
                             detail: "\(slot.wrappedAccount) present or unreadable; not replaced")
            throw Failure.keyUnavailable
        }
        // A caller that can see records sealed under a key this slot no
        // longer holds refuses the mint here, because a fresh key would
        // leave those records sealed with nothing able to open them.
        guard mintRefusedWhen() == false else {
            VaultLog.failure(.keychainWriteFailed,
                             detail: "\(slot.wrappedAccount) absent while sealed records name another key")
            throw Failure.keyUnavailable
        }
        let key = adopting() ?? SymmetricKey(size: .bits256)
        return try store(raw: key.withUnsafeBytes { Data($0) }, in: slot)
    }

    /// Stores these bytes as the slot's key: wrapped where the Enclave
    /// exists, raw otherwise, and read back before they are trusted. Both
    /// accounts are add-only, so a slot that already holds a key refuses.
    /// The raw account is reached only when the Enclave cannot make or use
    /// a key. A Keychain that refuses or will not answer, which is what a
    /// locked iPhone gives, throws and stores nothing raw.
    static func store(raw: Data, in slot: Slot) throws -> Loaded {
        if isAvailable, let wrapped = try wrap(raw, slot: slot) {
            let added = KeychainGeneric.add(service: slot.service, account: slot.wrappedAccount, data: wrapped)
            if added == .stored,
               let stored = KeychainGeneric.get(service: slot.service, account: slot.wrappedAccount),
               let roundTrip = unwrap(stored, slot: slot),
               roundTrip == raw {
                return Loaded(key: SymmetricKey(data: raw), wrappedByEnclave: true)
            }
            // Asked before anything is removed, so a record this call is
            // about to delete cannot read as an explicit absence.
            let answered = keychainAnswers(for: slot)
            // Only what this call added comes out again. A duplicate is a
            // key that appeared meanwhile, and nothing beside it is touched.
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
        // An add that fails leaves whatever is there alone: a duplicate is
        // a key that appeared meanwhile and is never deleted here. Only an
        // add that landed and then read back wrongly is taken out again.
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

    /// True when both wrapped-path accounts give an explicit answer. The
    /// locked-device answer is neither found nor absent, and it reads false.
    private static func keychainAnswers(for slot: Slot) -> Bool {
        for account in [slot.wrappedAccount, slot.privateKeyAccount] {
            if case .unavailable = KeychainGeneric.read(service: slot.service, account: account) {
                return false
            }
        }
        return true
    }

    /// Nil when the Enclave cannot make or use a key, which lets the caller
    /// fall to the raw account. Throws when the Keychain refuses the Enclave
    /// record, which lets nothing fall anywhere.
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

    /// Add-only, so an Enclave record beside a wrapped key is never written
    /// over. A record with no wrapped key beside it wraps nothing, and it
    /// gives way once.
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

    /// The stored shape of a wrapped key, with the field names LockerStore
    /// wrote before this file existed, so every Locker key wrapped by an
    /// earlier build still opens.
    private struct Pack: Codable {
        var ephPub: Data
        var box: Data
    }
}

/// Generic-password Keychain items, this device only, never synchronised.
/// Every read and every write of a key or a sealed item in this app goes
/// through here, so the rule below is stated once. Written once in each key
/// store it drifted into three wordings of one rule.
enum KeychainGeneric {

    /// What the Keychain actually answered.
    ///
    /// The distinction that matters is `notFound` against `unavailable`. A
    /// read fails either because nothing is stored, or because iOS will not
    /// hand the item over yet, which is what it says during app prewarming,
    /// a background launch, and the moment after the app resigns active.
    /// Collapsing those two into one `nil` is what lets a live key look
    /// absent and be replaced, so nothing here collapses them and every
    /// caller mints only on `notFound`.
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

    /// Adds an item and refuses to touch one already there. A key goes
    /// through this and never through `set`, because an update on a key
    /// account replaces the only copy of the key every blob was sealed with.
    /// A sealed Locker item goes through it for the same reason: every item
    /// is written once under a fresh identifier and never rewritten, so a
    /// duplicate account is a hard failure and never an update.
    @discardableResult
    static func addOnly(service: String, account: String, data: Data) -> Bool {
        add(service: service, account: account, data: data) == .stored
    }

    /// What an add-only write answered. `refused` is every answer that is
    /// neither a stored item nor a duplicate, the locked-device answer
    /// included.
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

    /// Adds or replaces. The lists of held keys take this, since each write
    /// carries the whole list. No key account and no Enclave record does.
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

    /// Removes one item. A Keychain item outlives the app's own files, so a
    /// delete that fails leaves a sealed secret behind indefinitely. That
    /// cannot be fixed here, and it must not be invisible.
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

    /// Removes every item one service owns, which is how a fresh install
    /// clears a previous one's keys and secrets together. False when the
    /// Keychain refused, so the caller retries on a later launch.
    static func deleteService(_ service: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service
        ]
        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
    }
}
