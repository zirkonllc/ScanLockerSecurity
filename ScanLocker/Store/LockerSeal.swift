//
//  LockerSeal.swift
//  ScanLocker
//
//  The seal a Locker secret is written behind, and the key that opens it for
//  as long as one item is on show.
//

import CryptoKit
import Foundation
import Security

enum LockerSeal {
    /// Conservative Keychain item budget. The Secure Enclave itself only holds keys.
    /// A seed is JSON (`words: [String]`) AES-GCM-sealed into one Keychain
    /// generic-password item (`item.{uuid}`). Not SQLite. Not one row per word.
    static let maxPlaintextBytes = 3072
    /// User-facing entry cap: 99% of the Keychain item budget. The budget is
    /// measured on the exact bytes that would be written, so 100% would work
    /// today; the reserve absorbs any future change to the payload shape or
    /// the encoder, so an item saved right at the line can always be opened,
    /// edited, and saved again.
    static var entryLimitBytes: Int { maxPlaintextBytes * 99 / 100 }

    /// How much of the budget a payload uses, measured on the encoded bytes
    /// that would actually be written — not on characters, which can each be
    /// 1 to 4 bytes. `measured == false` means encoding itself failed; that
    /// payload is treated as over the limit so nothing unverified is saved.
    struct PayloadBudget {
        let usedBytes: Int
        let limitBytes: Int
        let measured: Bool

        var fits: Bool { measured && usedBytes <= limitBytes }
        var overBytes: Int { max(0, usedBytes - limitBytes) }
    }

    /// The last payload measured and what it measured, so the places that
    /// ask about one draft encode it once between them.
    ///
    /// The budget bar asks inside the view body, which runs on every render
    /// and not only on every change, and Save and a paste ask again of the
    /// same payload. The answer is a pure function of the payload, so holding
    /// the last one is exact, and one entry is enough because only one item is
    /// edited at a time. All callers are main-actor.
    private static var lastMeasured: (payload: LockerPayload, budget: PayloadBudget)?

    /// What the last start-over placed back in Vault, and what it could not
    /// reach.
    ///
    /// A sweep the deadline stops, and a blob that will not open, leave those
    /// blobs in the Keychain and count them. A count abandoned without being
    /// recorded is the same failure as the sweep hanging, one screen further
    /// on, so the answer is held until a lock clears it. It carries no title,
    /// no date of the owner's and nothing out of a payload. All callers are
    /// main-actor, as they are for `lastMeasured`.
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

    /// Drops the last measured payload, which is the form's live draft and,
    /// after a save, the whole secret. It is dropped when the item is saved,
    /// when the form closes and when the session locks, so the draft does
    /// not outlive the screen that typed it.
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

    /// One encoder and one decoder for every locker payload. The budget
    /// check runs on each keystroke, so building a fresh coder per call cost
    /// an allocation for every character typed into a secret. All callers are
    /// main-actor.
    private static let jsonEncoder = JSONEncoder()
    private static let jsonDecoder = JSONDecoder()

    static var usesSecureEnclave: Bool { SecureEnclave.isAvailable && seKeyPresent }

    private static var seKeyPresent = false
    private static let service = (Bundle.main.bundleIdentifier ?? "Zirkon.ScanLocker") + ".locker"

    /// Seals one item and stores it. `inVaultFolder` chooses the key: an item
    /// filed in Vault is sealed under the Locker's Vault key and every
    /// other item under the Locker's tab key. The choice is made once, here,
    /// from the folder the item is being filed in, and nothing is ever
    /// moved into or out of Vault, so a key is never reconsidered after
    /// the seal.
    static func save(id: UUID, payload: LockerPayload, inVaultFolder: Bool) throws -> Int {
        let data = try jsonEncoder.encode(payload)
        guard data.count <= maxPlaintextBytes else {
            throw LockerError.tooLarge
        }
        // Sealed in the shape every stored blob takes, bound to the item's
        // own identifier, so the blob opens only under the record it was
        // sealed for.
        let sealed = try encrypt(data, name: id.uuidString, inVaultFolder: inVaultFolder)
        let stored = try storeSealedItem(id: id, sealed: sealed)
        forgetLastMeasured()
        return stored
    }

    /// Reads one sealed item.
    ///
    /// The two answers the Keychain can give for "no data" are kept apart
    /// here, because collapsing them is what made an ordinary locked device
    /// look like tampering. `keychainGet` returns nil for both "there is no
    /// such item" and "the Keychain will not answer right now" — and the
    /// second is what iOS says during a prewarm, a background launch, or the
    /// moment after the app resigns active, all of which are normal. The key
    /// stores three doors down already read this distinction correctly; the
    /// items did not.
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

    /// Removes one sealed item and says whether the Keychain did it. A
    /// caller that is about to drop the row must know, because a row dropped
    /// over a secret that stayed leaves that secret with nothing able to
    /// name it.
    @discardableResult
    static func delete(id: UUID) -> Bool {
        KeychainGeneric.delete(service: service, account: "item.\(id.uuidString)")
    }

    // MARK: Sealed bytes, moved without being opened
    //
    // A copy of the Locker kept outside this phone carries each item's
    // sealed bytes exactly as the Keychain holds them, and a restore puts
    // them back the same way. The two functions below are the only reads
    // and writes that touch an item without opening it, so the path that
    // carries an item off the phone never holds its plaintext and needs no
    // key, and the path that brings one back stores what it was given.

    /// One item's Keychain bytes as stored, in the envelope they were
    /// sealed in, never opened. The Keychain's two answers for "no data"
    /// come back as they are, so a caller tells an item that is not there
    /// from a Keychain that will not answer.
    static func sealedItemData(id: UUID) -> KeychainGeneric.Read {
        KeychainGeneric.read(service: service, account: "item.\(id.uuidString)")
    }

    /// Stores bytes already sealed, verbatim, under this identifier, and
    /// returns how many were stored. Add-only like `save`: an identifier
    /// already holding an item is a hard failure and never an overwrite.
    /// The caller has verified that the bytes open under the key their
    /// envelope names; this writes them, reads them back, and judges
    /// nothing about what is inside.
    static func storeSealedItem(id: UUID, sealed: Data) throws -> Int {
        let account = "item.\(id.uuidString)"
        guard KeychainGeneric.addOnly(service: service, account: account, data: sealed) else {
            throw LockerError.keychainWriteFailed
        }
        guard KeychainGeneric.get(service: service, account: account) == sealed else {
            KeychainGeneric.delete(service: service, account: account)
            throw LockerError.keychainWriteFailed
        }
        // Equal bytes prove the Keychain kept what it was handed. They do not
        // prove the item opens, so the stored bytes are opened under the key
        // their envelope names before the caller is told the secret landed.
        guard let keys = try? durableKeys(),
              let keyID = SealedEnvelope.keyID(in: sealed),
              let key = keys.ring[keyID],
              let _ = try? SealedEnvelope.open(sealed, key: key, name: id.uuidString) else {
            KeychainGeneric.delete(service: service, account: account)
            throw LockerError.keychainWriteFailed
        }
        return sealed.count
    }

    /// Opens bytes sealed under `oldID`, seals them again under the same
    /// key and `newID`, and stores them. The one case where a restored item
    /// must take a fresh identifier.
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

    // MARK: Reaching the blobs when the catalog cannot name them
    //
    // A catalog that will not open leaves every sealed blob in the Keychain
    // with nothing able to name it. The three functions below are the whole
    // of what the rescue in `startLockerCatalogOver` reaches for: the blobs
    // as they are stored, the identifier the Vault key stamps on the ones
    // that belong to it, and an open that accepts that key and no other.
    // `VaultBoxRescue` holds the rules they are used under.

    /// Every stored item this service holds, still sealed, with the moment the
    /// Keychain recorded for it.
    ///
    /// One query for all of them, because a query per item would be one round
    /// trip per secret. Nothing here opens anything, and the key records this
    /// service also holds are passed over, since only an item account names a
    /// blob. A Keychain that will not answer gives an empty list, and the
    /// rescue then places nothing and leaves every blob where it is.
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

    /// Whether this service still holds a sealed item that none of `known`
    /// can open, with no blob returned.
    ///
    /// A Keychain that will not answer is read as holding one. The two
    /// callers act on the answer by refusing to write and refusing to mint,
    /// so an unanswered Keychain must never read as an empty one.
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

    /// The identifier the Vault key stamps on every blob it seals, which
    /// places a blob in the folder without opening it.
    static func vaultBoxKeyID() -> Data? {
        guard let keys = try? durableKeys() else { return nil }
        return SealedEnvelope.keyID(of: keys.vaultFolder)
    }

    /// Opens a blob under the Vault key, and under no other, bound to the
    /// identifier it was sealed with.
    ///
    /// The ring `decrypt` opens against holds both Locker keys and every twin
    /// beside them, and that is what a rescue must not use: a blob sealed
    /// under the tab key would open there and be filed in a folder it was
    /// never in. Naming the one key refuses it instead. The payload is handed
    /// straight back to the caller that reads its shape and releases it.
    static func openInVaultBox(_ blob: VaultBoxRescue.Blob, id: UUID) -> LockerPayload? {
        guard let keys = try? durableKeys(),
              let plain = try? SealedEnvelope.open(blob.sealed, key: keys.vaultFolder, name: id.uuidString)
        else { return nil }
        return try? jsonDecoder.decode(LockerPayload.self, from: plain)
    }

    /// Whether one stored item opens under the Vault key, and under no
    /// other. Nil when the Keychain holds no record for it. The plaintext is
    /// released here and never returned.
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

    /// Seals bytes under the tab key for the copy, bound to `name`. The
    /// Locker's cloud catalog goes up through here. Never the Vault key.
    static func sealForCloud(_ plaintext: Data, name: String) throws -> Data {
        let keys = try durableKeys()
        do {
            return try SealedEnvelope.seal(plaintext, key: keys.tab, name: name)
        } catch {
            throw LockerError.sealFailed
        }
    }

    /// The Locker's catalog, sealed under the Locker's tab key and bound to
    /// its file name. It names every item, its folder and its title, so the
    /// key that opens it is the Locker's own and never Scan's.
    static func sealCatalog(_ plaintext: Data) throws -> Data {
        try encrypt(plaintext, name: EncryptedVaultStorage.lockerIndexName, inVaultFolder: false)
    }

    /// The catalog, opened under whichever Locker key its header names.
    static func openCatalog(_ sealed: Data) throws -> Data {
        try decrypt(sealed, name: EncryptedVaultStorage.lockerIndexName)
    }

    /// Opens bytes that came down from the copy under whichever key in the
    /// cloud ring their header names, which never includes the Vault
    /// key. The verification every restored item passes.
    static func openFromCloud(_ sealed: Data, name: String) throws -> Data {
        let keys = try durableKeys()
        return try SealedEnvelope.open(sealed, ring: keys.cloudRing, name: name)
    }

    /// Whether the cloud ring holds the key a blob's header names.
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

    /// Opens under whichever Locker key the blob's own header names.
    private static func decrypt(_ sealed: Data, name: String) throws -> Data {
        let keys = try durableKeys()
        return try SealedEnvelope.open(sealed, ring: keys.ring, name: name)
    }

    // MARK: The Locker's two keys
    //
    // The tab key seals every item outside Vault and the Vault key
    // seals every item inside it. Both are Enclave-wrapped and device-only
    // through EnclaveKeyWrap, each in its own slot with its own Enclave
    // key, so removing one never touches the other. The Vault key is
    // never synchronised, escrowed or placed in any ring that leaves this
    // phone.

    /// The tab key's slot, with the accounts and label every Locker key
    /// before this build was stored under, so an existing Locker opens.
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

    /// Both keys, and the ring that maps each key's identifier to it. The
    /// two local keys are derived once and kept until a lock purges them;
    /// the ring around them is rebuilt from the Keychain by `reloadRing`.
    private struct Keys {
        let tab: SymmetricKey
        let vaultFolder: SymmetricKey
        var ring: [Data: SymmetricKey]

        /// The ring a blob from the cloud may open under: everything but
        /// the Vault key, whose blobs never travel.
        var cloudRing: [Data: SymmetricKey] {
            var out = ring
            out.removeValue(forKey: SealedEnvelope.keyID(of: vaultFolder))
            return out
        }
    }

    private static let heldAccount = "aes.held.v1"

    /// What the held-key account answered: the keys it holds, nothing
    /// stored, or an answer the reader cannot use.
    ///
    /// The three are kept apart because a writer has to tell them apart.
    /// `unreadable` covers the Keychain refusing the item and a record that
    /// will not decode. Either way keys may be stored that this read did not
    /// see, and a write built on that read would drop them.
    enum HeldRead {
        case keys([SymmetricKey])
        case absent
        case unreadable
    }

    /// Every key this phone holds for itself beyond its two local keys:
    /// twins written down by a restore, so a blob restored under another
    /// phone's key stays readable here after that phone withdraws its
    /// twin. Raw tab keys, device-only. No Vault key ever comes this way.
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

    /// The held keys for a reader building the ring. An answer it cannot use
    /// reads as none, which closes the ring around the keys it does have: a
    /// blob whose key is missing refuses to open and is kept.
    private static func heldKeys() -> [SymmetricKey] {
        if case .keys(let keys) = heldRead() { return keys }
        return []
    }

    /// Writes every twin for the Locker into the held keys, read back
    /// before it is trusted. True when every twin is held afterwards.
    ///
    /// The write carries the keys already held, so it begins by reading
    /// them. An answer the reader cannot use ends it here: writing the twins
    /// alone over an account whose contents were not seen would drop every
    /// key this phone had written down for restored material, and the blobs
    /// sealed under them would never open again.
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

    /// The ring around two local keys: every twin the Keychain holds for
    /// the Locker, every held key, then the two local keys, written last so
    /// a local key wins its own identifier.
    /// Whether minting a Vault key now would leave sealed items behind
    /// that nothing could open. Every key this phone can already reach is
    /// counted, so only a record naming a key that is gone refuses the mint.
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
    /// Guards `cached` and `seKeyPresent`. The transfer seals payloads off
    /// the main thread while the main thread can purge the cached keys on
    /// resign-active, so the cache is not main-only state.
    private static let keyLock = NSLock()

    /// Loads or creates both keys, only if the Keychain stores them and
    /// reads them back.
    static func prepareWrappingKey() -> Bool {
        do {
            _ = try durableKeys()
            return true
        } catch {
            VaultLog.failure(.keychainWriteFailed, detail: "locker keys not stored")
            return false
        }
    }

    /// Seals and opens one blob under each Locker key with a name as
    /// authenticated data. Run at launch; a mismatch refuses the launch.
    static func selfTest() -> Bool {
        guard let keys = try? durableKeys() else { return false }
        return SealedEnvelope.selfTest(keys: [keys.tab, keys.vaultFolder])
    }

    /// Adds the synchronisable twin of the tab key, raw, so iCloud Keychain
    /// carries it. The local item stays wrapped as it is. The Vault key
    /// has no twin and never gains one.
    static func publishTwin() -> Bool {
        guard let keys = try? durableKeys() else { return false }
        return KeyTwin.publish(keys.tab, tab: .locker)
    }

    /// Removes the tab key's twin and nothing else.
    static func withdrawTwin() -> Bool {
        guard let keys = try? durableKeys() else { return false }
        return KeyTwin.withdraw(keyID: SealedEnvelope.keyID(of: keys.tab), tab: .locker)
    }

    /// Reads the ring back from the Keychain, so a twin that arrived since
    /// launch joins it. Called before every cloud operation. The two local
    /// keys are kept as they are; only the ring around them is read again,
    /// so no Enclave unwrap runs for this.
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
            // The tab key first, so a Locker written before the Vault key
            // existed opens with its key and then mints the second beside
            // it. A phone with no local tab key adopts a twin when the
            // Keychain holds one, and mints only when it holds none.
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
        // The Vault key is in the ring so its blobs open, and in nothing
        // that leaves the phone.
        let keys = Keys(tab: tab.key, vaultFolder: vaultFolder.key, ring: ring(around: tab.key, vaultFolder.key))
        cached = keys
        return keys
    }

    /// Drops the in-memory copies of both unwrapped Locker keys. Called when
    /// the app leaves the foreground: the keys re-derive from the Keychain
    /// (and the Secure Enclave, where present) on the next access, so nothing
    /// is lost — they simply stop sitting in this process's memory while the
    /// app is not being used. The Keychain records are untouched, and
    /// `EnclaveKeyWrap.loadOrCreate` can never mint a replacement while one
    /// exists.
    static func purgeCachedKey() {
        keyLock.lock()
        cached = nil
        keyLock.unlock()
        forgetLastMeasured()
        forgetVaultBoxRescue()
    }

    /// Fresh-install wipe: removes every Keychain item this service owns,
    /// which takes both keys, both Enclave keys and the held keys together.
    /// Returns false when the Keychain refused, so the caller leaves the
    /// install unmarked and retries on a later launch.
    static func wipeForFreshInstall() -> Bool {
        keyLock.lock()
        cached = nil
        seKeyPresent = false
        keyLock.unlock()
        // The erase promises that nothing is kept, so the record of the last
        // rescue goes with the keys rather than waiting for the next lock.
        forgetVaultBoxRescue()
        return KeychainGeneric.deleteService(service)
    }

}
