import CryptoKit
import Foundation
import Security

enum LockerSeal {
    static let maxPlaintextBytes = 3730
    static var entryLimitBytes: Int { maxPlaintextBytes * 99 / 100 }

    struct PayloadBudget {
        let usedBytes: Int
        let limitBytes: Int
        let measured: Bool

        var fits: Bool { measured && usedBytes <= limitBytes }
        var overBytes: Int { max(0, usedBytes - limitBytes) }
    }

    private static var lastMeasured: (payload: LockerPayload, budget: PayloadBudget)?

    private(set) static var lastVaultBoxRescue: VaultBoxRescue.Sweep?

    static func recordVaultBoxRescue(_ sweep: VaultBoxRescue.Sweep) {
        lastVaultBoxRescue = sweep
    }

    static func forgetVaultBoxRescue() {
        lastVaultBoxRescue = nil
    }

    static func budget(of payload: LockerPayload) -> PayloadBudget {
        if let last = lastMeasured, last.payload == payload { return last.budget }
        let measured = measure(payload)
        lastMeasured = (payload, measured)
        return measured
    }

    static func forgetLastMeasured() {
        lastMeasured = nil
    }

    private static func measure(_ payload: LockerPayload) -> PayloadBudget {
        guard let data = try? jsonEncoder.encode(payload) else {
            return PayloadBudget(
                usedBytes: maxPlaintextBytes + 1,
                limitBytes: entryLimitBytes,
                measured: false
            )
        }
        return PayloadBudget(
            usedBytes: data.count,
            limitBytes: entryLimitBytes,
            measured: true
        )
    }

    private static let jsonEncoder = JSONEncoder()
    private static let jsonDecoder = JSONDecoder()

    static var usesSecureEnclave: Bool { SecureEnclave.isAvailable && seKeyPresent }

    private static var seKeyPresent = false
    private static let service = (Bundle.main.bundleIdentifier ?? "Zirkon.ScanLocker") + ".locker"

    static func save(id: UUID, payload: LockerPayload, inVaultFolder: Bool) throws -> Int {
        let data = try jsonEncoder.encode(payload)
        guard data.count <= maxPlaintextBytes else {
            throw LockerError.tooLarge
        }
        let sealed = try encrypt(data, name: id.uuidString, inVaultFolder: inVaultFolder)
        let stored = try storeSealedItem(id: id, sealed: sealed)
        forgetLastMeasured()
        return stored
    }

    static func load(id: UUID) throws -> LockerPayload {
        switch KeychainGeneric.read(service: service, account: "item.\(id.uuidString)") {
        case .found(let sealed):
            let data = try decrypt(sealed, name: id.uuidString)
            return try jsonDecoder.decode(LockerPayload.self, from: data)
        case .notFound:
            throw LockerError.missing
        case .unavailable:
            throw LockerError.keychainWriteFailed
        }
    }

    @discardableResult
    static func delete(id: UUID) -> Bool {
        KeychainGeneric.delete(service: service, account: "item.\(id.uuidString)")
    }

    static func sealedItemData(id: UUID) -> KeychainGeneric.Read {
        KeychainGeneric.read(service: service, account: "item.\(id.uuidString)")
    }

    static func storeSealedItem(id: UUID, sealed: Data) throws -> Int {
        let account = "item.\(id.uuidString)"
        guard KeychainGeneric.addOnly(service: service, account: account, data: sealed) else {
            throw LockerError.keychainWriteFailed
        }
        guard KeychainGeneric.get(service: service, account: account) == sealed else {
            KeychainGeneric.delete(service: service, account: account)
            throw LockerError.keychainWriteFailed
        }
        guard let keys = try? durableKeys(),
              let keyID = SealedEnvelope.keyID(in: sealed),
              let key = keys.ring[keyID],
              let _ = try? SealedEnvelope.open(sealed, key: key, name: id.uuidString) else {
            KeychainGeneric.delete(service: service, account: account)
            throw LockerError.keychainWriteFailed
        }
        return sealed.count
    }

    static func resealAndStore(_ sealed: Data, from oldID: UUID, to newID: UUID) throws -> Int {
        let keys = try durableKeys()
        guard let id = SealedEnvelope.keyID(in: sealed), let key = keys.ring[id] else {
            throw LockerError.keychainWriteFailed
        }
        let plain = try SealedEnvelope.open(sealed, key: key, name: oldID.uuidString)
        let resealed: Data
        do {
            resealed = try SealedEnvelope.seal(plain, key: key, name: newID.uuidString)
        } catch {
            throw LockerError.sealFailed
        }
        return try storeSealedItem(id: newID, sealed: resealed)
    }

    static func storedBlobs() -> [VaultBoxRescue.Blob] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecReturnAttributes as String: true,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let rows = result as? [[String: Any]] else { return [] }
        return rows.compactMap { row in
            guard let account = row[kSecAttrAccount as String] as? String,
                  VaultBoxRescue.identifier(inAccount: account) != nil,
                  let sealed = row[kSecValueData as String] as? Data else { return nil }
            let created = row[kSecAttrCreationDate as String] as? Date ?? Date()
            return VaultBoxRescue.Blob(account: account, sealed: sealed, createdAt: created)
        }
    }

    static func holdsSealedItems(outsideKeyIDs known: Set<Data> = []) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecReturnAttributes as String: true,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return false }
        guard status == errSecSuccess, let rows = result as? [[String: Any]] else { return true }
        return rows.contains { row in
            guard let account = row[kSecAttrAccount as String] as? String,
                  VaultBoxRescue.identifier(inAccount: account) != nil else { return false }
            guard let sealed = row[kSecValueData as String] as? Data,
                  let keyID = SealedEnvelope.keyID(in: sealed) else { return true }
            return known.contains(keyID) == false
        }
    }

    static func vaultBoxKeyID() -> Data? {
        guard let keys = try? durableKeys() else { return nil }
        return SealedEnvelope.keyID(of: keys.vaultFolder)
    }

    static func openInVaultBox(_ blob: VaultBoxRescue.Blob, id: UUID) -> LockerPayload? {
        guard let keys = try? durableKeys(),
              let plain = try? SealedEnvelope.open(blob.sealed, key: keys.vaultFolder, name: id.uuidString)
        else { return nil }
        return try? jsonDecoder.decode(LockerPayload.self, from: plain)
    }

    static func opensUnderVaultKey(id: UUID) -> Bool? {
        switch KeychainGeneric.read(service: service, account: "item.\(id.uuidString)") {
        case .found(let sealed):
            guard let keys = try? durableKeys() else { return false }
            return (try? SealedEnvelope.open(sealed, key: keys.vaultFolder, name: id.uuidString)) != nil
        case .notFound:
            return nil
        case .unavailable:
            return false
        }
    }

    static func sealForCloud(_ plaintext: Data, name: String) throws -> Data {
        let keys = try durableKeys()
        do {
            return try SealedEnvelope.seal(plaintext, key: keys.tab, name: name)
        } catch {
            throw LockerError.sealFailed
        }
    }

    static func sealCatalog(_ plaintext: Data) throws -> Data {
        try encrypt(plaintext, name: EncryptedVaultStorage.lockerIndexName, inVaultFolder: false)
    }

    static func openCatalog(_ sealed: Data) throws -> Data {
        try decrypt(sealed, name: EncryptedVaultStorage.lockerIndexName)
    }

    static func openFromCloud(_ sealed: Data, name: String) throws -> Data {
        let keys = try durableKeys()
        return try SealedEnvelope.open(sealed, ring: keys.cloudRing, name: name)
    }

    static func cloudRingHolds(keyID: Data) -> Bool {
        (try? durableKeys())?.cloudRing[keyID] != nil
    }

    private static func encrypt(_ plaintext: Data, name: String, inVaultFolder: Bool) throws -> Data {
        let keys = try durableKeys()
        do {
            return try SealedEnvelope.seal(plaintext, key: inVaultFolder ? keys.vaultFolder : keys.tab, name: name)
        } catch {
            throw LockerError.sealFailed
        }
    }

    private static func decrypt(_ sealed: Data, name: String) throws -> Data {
        let keys = try durableKeys()
        return try SealedEnvelope.open(sealed, ring: keys.ring, name: name)
    }

    static let tabSlot = EnclaveKeyWrap.Slot(
        service: service,
        wrappedAccount: "aes.wrapped.v1",
        rawAccount: "aes.raw.v1",
        privateKeyAccount: "se.priv.v1",
        label: "scanlocker.locker.wrap.v1"
    )

    static let vaultFolderSlot = EnclaveKeyWrap.Slot(
        service: service,
        wrappedAccount: "aes.staybox.wrapped.v1",
        rawAccount: "aes.staybox.raw.v1",
        privateKeyAccount: "se.staybox.v1",
        label: "scanlocker.locker.staybox.wrap.v1"
    )

    private struct Keys {
        let tab: SymmetricKey
        let vaultFolder: SymmetricKey
        var ring: [Data: SymmetricKey]

        var cloudRing: [Data: SymmetricKey] {
            var out = ring
            out.removeValue(forKey: SealedEnvelope.keyID(of: vaultFolder))
            return out
        }
    }

    private static let heldAccount = "aes.held.v1"

    enum HeldRead {
        case keys([SymmetricKey])
        case absent
        case unreadable
    }

    private static func heldRead() -> HeldRead {
        switch KeychainGeneric.read(service: service, account: heldAccount) {
        case .notFound:
            return .absent
        case .unavailable:
            return .unreadable
        case .found(let data):
            guard let raws = try? JSONDecoder().decode([Data].self, from: data) else {
                VaultLog.failure(.decryptFailed, detail: "held locker keys did not decode")
                return .unreadable
            }
            return .keys(raws.filter { $0.count == 32 }.map { SymmetricKey(data: $0) })
        }
    }

    private static func heldKeys() -> [SymmetricKey] {
        if case .keys(let keys) = heldRead() { return keys }
        return []
    }

    static func holdTwinsLocally() -> Bool {
        let twins = KeyTwin.twins(for: .locker)
        guard twins.isEmpty == false else { return true }
        var held: [SymmetricKey]
        switch heldRead() {
        case .keys(let keys): held = keys
        case .absent: held = []
        case .unreadable:
            VaultLog.failure(.keychainWriteFailed, detail: "held locker keys did not read")
            return false
        }
        let known = Set(held.map { SealedEnvelope.keyID(of: $0) })
        for (id, twin) in twins where known.contains(id) == false {
            held.append(twin)
        }
        let raws = held.map { $0.withUnsafeBytes { Data($0) } }
        guard let data = try? JSONEncoder().encode(raws),
              KeychainGeneric.set(service: service, account: heldAccount, data: data),
              KeychainGeneric.get(service: service, account: heldAccount) == data else {
            VaultLog.failure(.keychainWriteFailed, detail: "held locker keys not stored")
            return false
        }
        reloadRing()
        return true
    }

    private static func mintWouldOrphanRecords(besides tab: SymmetricKey) -> Bool {
        var known = Set(KeyTwin.twins(for: .locker).keys)
        for held in heldKeys() { known.insert(SealedEnvelope.keyID(of: held)) }
        known.insert(SealedEnvelope.keyID(of: tab))
        return holdsSealedItems(outsideKeyIDs: known)
    }

    private static func ring(around tab: SymmetricKey, _ vaultFolder: SymmetricKey) -> [Data: SymmetricKey] {
        var ring = KeyTwin.twins(for: .locker)
        for held in heldKeys() { ring[SealedEnvelope.keyID(of: held)] = held }
        ring[SealedEnvelope.keyID(of: tab)] = tab
        ring[SealedEnvelope.keyID(of: vaultFolder)] = vaultFolder
        return ring
    }

    private static var cached: Keys?
    private static let keyLock = NSLock()

    static func prepareWrappingKey() -> Bool {
        do {
            _ = try durableKeys()
            return true
        } catch {
            VaultLog.failure(.keychainWriteFailed, detail: "locker keys not stored")
            return false
        }
    }

    static func selfTest() -> Bool {
        guard let keys = try? durableKeys() else { return false }
        return SealedEnvelope.selfTest(keys: [keys.tab, keys.vaultFolder])
    }

    static func publishTwin() -> Bool {
        guard let keys = try? durableKeys() else { return false }
        return KeyTwin.publish(keys.tab, tab: .locker)
    }

    static func withdrawTwin() -> Bool {
        guard let keys = try? durableKeys() else { return false }
        return KeyTwin.withdraw(keyID: SealedEnvelope.keyID(of: keys.tab), tab: .locker)
    }

    static func reloadRing() {
        keyLock.lock()
        defer { keyLock.unlock() }
        guard let keys = cached else { return }
        cached = Keys(tab: keys.tab, vaultFolder: keys.vaultFolder, ring: ring(around: keys.tab, keys.vaultFolder))
    }

    private static func durableKeys() throws -> Keys {
        keyLock.lock()
        defer { keyLock.unlock() }
        if let cached { return cached }
        let tab: EnclaveKeyWrap.Loaded
        let vaultFolder: EnclaveKeyWrap.Loaded
        do {
            tab = try EnclaveKeyWrap.loadOrCreate(in: tabSlot,
                                                  adopting: { KeyTwin.twinToAdopt(for: .locker) })
            let tabKey = tab.key
            vaultFolder = try EnclaveKeyWrap.loadOrCreate(
                in: vaultFolderSlot,
                mintRefusedWhen: { mintWouldOrphanRecords(besides: tabKey) })
        } catch {
            throw LockerError.keychainWriteFailed
        }
        seKeyPresent = tab.wrappedByEnclave
        let keys = Keys(tab: tab.key, vaultFolder: vaultFolder.key, ring: ring(around: tab.key, vaultFolder.key))
        cached = keys
        return keys
    }

    static func purgeCachedKey() {
        keyLock.lock()
        cached = nil
        keyLock.unlock()
        forgetLastMeasured()
        forgetVaultBoxRescue()
    }

    static func wipeForFreshInstall() -> Bool {
        keyLock.lock()
        cached = nil
        seKeyPresent = false
        keyLock.unlock()
        forgetVaultBoxRescue()
        return KeychainGeneric.deleteService(service)
    }

}
