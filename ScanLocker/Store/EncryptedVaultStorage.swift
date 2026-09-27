import CryptoKit
import Foundation
import UIKit

final class EncryptedVaultStorage {
    private var cachedKey: SymmetricKey?
    private var cachedVaultFolderKey: SymmetricKey?
    private var ring: [Data: SymmetricKey] = [:]
    private let ringLock = NSLock()
    private let rootURL: URL
    private let photosDir: URL
    private let metaURL: URL
    private let lockerURL: URL

    static var containerURL: URL {
        FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("ScanLocker", isDirectory: true)
    }

    static var vaultIndexURL: URL { containerURL.appendingPathComponent("vault.enc") }
    static var lockerIndexURL: URL { containerURL.appendingPathComponent("locker.enc") }
    static var trustedIndexURL: URL { containerURL.appendingPathComponent("trusted.enc") }
    static var auditIndexURL: URL { containerURL.appendingPathComponent("audit.enc") }

    let isDurableKeyReady: Bool

    init() {
        let tab = Self.loadOrCreateKey()
        let vaultFolder = Self.loadOrCreateVaultFolderKey()
        self.cachedKey = tab
        self.cachedVaultFolderKey = vaultFolder
        self.isDurableKeyReady = tab != nil && vaultFolder != nil

        let base = Self.containerURL
        self.rootURL = base
        self.photosDir = base.appendingPathComponent("photos", isDirectory: true)
        self.metaURL = Self.vaultIndexURL
        self.lockerURL = Self.lockerIndexURL

        try? FileManager.default.createDirectory(at: photosDir,
                                                 withIntermediateDirectories: true)
        excludeFromBackup()
        reloadRing()
    }

    private func loadedKeysLocked() -> (tab: SymmetricKey, vaultFolder: SymmetricKey)? {
        if let cachedKey, let cachedVaultFolderKey { return (cachedKey, cachedVaultFolderKey) }
        #if DEBUG
        let began = DispatchTime.now().uptimeNanoseconds
        #endif
        guard let tab = Self.loadOrCreateKey(), let vaultFolder = Self.loadOrCreateVaultFolderKey() else {
            return nil
        }
        cachedKey = tab
        cachedVaultFolderKey = vaultFolder
        rebuildRingLocked(tab: tab, vaultFolder: vaultFolder)
        #if DEBUG
        let millis = Double(DispatchTime.now().uptimeNanoseconds - began) / 1_000_000
        print(String(format: "ScanLocker: Scan keys re-derived in %.1f ms", millis))
        #endif
        return (tab, vaultFolder)
    }

    private func rebuildRingLocked(tab: SymmetricKey, vaultFolder: SymmetricKey) {
        var fresh = KeyTwin.twins(for: .scan)
        for held in Self.heldKeys() {
            fresh[SealedEnvelope.keyID(of: held)] = held
        }
        fresh[SealedEnvelope.keyID(of: tab)] = tab
        fresh[SealedEnvelope.keyID(of: vaultFolder)] = vaultFolder
        ring = fresh
    }

    func reloadRing() {
        ringLock.lock()
        defer { ringLock.unlock() }
        guard let keys = loadedKeysLocked() else {
            ring = [:]
            return
        }
        rebuildRingLocked(tab: keys.tab, vaultFolder: keys.vaultFolder)
    }

    func purgeKeys() {
        ringLock.lock()
        cachedKey = nil
        cachedVaultFolderKey = nil
        ring = [:]
        ringLock.unlock()
    }

    private func requireKeys() throws -> (tab: SymmetricKey, vaultFolder: SymmetricKey) {
        ringLock.lock()
        defer { ringLock.unlock() }
        guard let keys = loadedKeysLocked() else { throw StorageError.keyUnavailable }
        return keys
    }

    private func currentRing() -> [Data: SymmetricKey] {
        ringLock.lock()
        defer { ringLock.unlock() }
        _ = loadedKeysLocked()
        return ring
    }

    private func cloudRing() -> [Data: SymmetricKey] {
        ringLock.lock()
        defer { ringLock.unlock() }
        guard let keys = loadedKeysLocked() else { return [:] }
        var ring = self.ring
        ring.removeValue(forKey: SealedEnvelope.keyID(of: keys.vaultFolder))
        return ring
    }

    private static let heldAccount = "scanlocker.aes.held.v1"

    enum HeldRead {
        case keys([SymmetricKey])
        case absent
        case unreadable
    }

    private static func heldRead() -> HeldRead {
        let answer = KeychainGeneric.read(service: service, account: heldAccount)
        switch answer {
        case .notFound:
            return .absent
        case .unavailable:
            return .unreadable
        case .found(let data):
            guard let raws = try? JSONDecoder().decode([Data].self, from: data) else {
                VaultLog.failure(.decryptFailed, detail: "held keys did not decode")
                return .unreadable
            }
            return .keys(raws.filter { $0.count == 32 }.map { SymmetricKey(data: $0) })
        }
    }

    private static func heldKeys() -> [SymmetricKey] {
        if case .keys(let keys) = heldRead() { return keys }
        return []
    }

    func holdTwinsLocally() -> Bool {
        let twins = KeyTwin.twins(for: .scan)
        guard twins.isEmpty == false else { return true }
        var held: [SymmetricKey]
        switch Self.heldRead() {
        case .keys(let keys): held = keys
        case .absent: held = []
        case .unreadable:
            VaultLog.failure(.keychainWriteFailed, detail: "held keys did not read")
            return false
        }
        let known = Set(held.map { SealedEnvelope.keyID(of: $0) })
        for (id, twin) in twins where known.contains(id) == false {
            held.append(twin)
        }
        let raws = held.map { $0.withUnsafeBytes { Data($0) } }
        guard let data = try? JSONEncoder().encode(raws),
              KeychainGeneric.set(service: Self.service, account: Self.heldAccount, data: data),
              KeychainGeneric.get(service: Self.service, account: Self.heldAccount) == data else {
            VaultLog.failure(.keychainWriteFailed, detail: "held keys not stored")
            return false
        }
        reloadRing()
        return true
    }

    var tabKeyID: Data? { (try? requireKeys()).map { SealedEnvelope.keyID(of: $0.tab) } }

    func publishTwin() -> Bool {
        guard let keys = try? requireKeys() else { return false }
        return KeyTwin.publish(keys.tab, tab: .scan)
    }

    func withdrawTwin() -> Bool {
        guard let tabKeyID else { return false }
        return KeyTwin.withdraw(keyID: tabKeyID, tab: .scan)
    }

    private static let retiredService = "Zirkon.VaultScan"

    static func wipeKeyForFreshInstall() -> Bool {
        let current = KeychainGeneric.deleteService(service)
        let retired = KeychainGeneric.deleteService(retiredService)
        return current && retired
    }

    func wipeKeys() -> Bool {
        let audit = loadAuditIndex()
        let trusted = loadTrustedIndex()
        ringLock.lock()
        cachedKey = nil
        cachedVaultFolderKey = nil
        ring = [:]
        let gone = Self.wipeKeyForFreshInstall()
        ringLock.unlock()
        guard gone else { return false }
        do {
            if case .loaded(let plain) = audit { try saveAuditIndex(plain) }
            if case .loaded(let plain) = trusted { try saveTrustedIndex(plain) }
        } catch {
            return false
        }
        return true
    }

    func selfTest() -> Bool {
        guard let keys = try? requireKeys() else { return false }
        return SealedEnvelope.selfTest(keys: [keys.tab, keys.vaultFolder])
    }

    func savePhoto(_ jpeg: Data, id: UUID, inVaultFolder: Bool) throws -> String {
        let filename = id.uuidString + ".enc"
        let sealed = try seal(jpeg, name: filename, key: try keyFor(inVaultFolder: inVaultFolder))
        let url = photosDir.appendingPathComponent(filename)
        try VaultRoom.write(sealed, to: url)
        applyExclusion(url, true)
        return filename
    }

    func pageJPEGByteCount(filename: String) -> Int {
        let url = photosDir.appendingPathComponent(filename)
        let sealed = (try? FileManager.default.attributesOfItem(atPath: url.path)[.size] as? Int) ?? 0
        return max(0, sealed - SealedEnvelope.headerLength - 12 - 16)
    }

    func pageFileExists(id: UUID) -> Bool {
        let url = photosDir.appendingPathComponent(id.uuidString + ".enc")
        return FileManager.default.fileExists(atPath: url.path)
    }

    var isShortOfRoom: Bool {
        (try? VaultRoom.require(VaultRoom.probeBytes, in: photosDir)) == nil
    }

    func deletePhoto(filename: String) {
        let url = photosDir.appendingPathComponent(filename)
        try? FileManager.default.removeItem(at: url)
        let thumb = photosDir.appendingPathComponent(Self.thumbnailFilename(for: filename))
        try? FileManager.default.removeItem(at: thumb)
    }

    func deletePhotosInBackground(filenames: [String]) {
        guard filenames.isEmpty == false else { return }
        DispatchQueue.global(qos: .utility).async { [self] in
            filenames.forEach { deletePhoto(filename: $0) }
        }
    }

    struct SealedPicture {
        let filename: String
        let thumbnail: UIImage?
    }

    func savePhotoResult(_ image: UIImage, id: UUID, inVaultFolder: Bool) -> Result<SealedPicture, VaultFailure> {
        let prepared = ScanImage.prepared(image, maxSide: ScanImage.decodeCeiling)
        guard let jpeg = prepared.jpegData(compressionQuality: 0.85) else {
            return .failure(.jpegEncodeFailed)
        }
        do {
            let key = try keyFor(inVaultFolder: inVaultFolder)
            let name = try savePhoto(jpeg, id: id, inVaultFolder: inVaultFolder)
            return .success(SealedPicture(filename: name,
                                          thumbnail: saveThumbnail(from: prepared, for: name, key: key)))
        } catch StorageError.keyUnavailable {
            SafeMode.reportAtUse(.keyStorage)
            return .failure(.keychainWriteFailed)
        } catch {
            return .failure(.sealWriteFailed)
        }
    }

    static func thumbnailFilename(for filename: String) -> String { "t-" + filename }

    @discardableResult
    func saveThumbnail(fromJPEG jpeg: Data, for filename: String) -> UIImage? {
        guard let key = keySealing(page: filename) else { return nil }
        return saveThumbnail(fromJPEG: jpeg, for: filename, key: key)
    }

    @discardableResult
    private func saveThumbnail(fromJPEG jpeg: Data, for filename: String, key: SymmetricKey) -> UIImage? {
        guard let small = ScanImage.decoded(jpeg, maxSide: ScanImage.thumbnailMaxSide) else { return nil }
        return saveThumbnail(small, for: filename, key: key) ? small : nil
    }

    @discardableResult
    private func saveThumbnail(from page: UIImage, for filename: String, key: SymmetricKey) -> UIImage? {
        let small = ScanImage.opaque(page, maxSide: ScanImage.thumbnailMaxSide)
        return saveThumbnail(small, for: filename, key: key) ? small : nil
    }

    private func keySealing(page filename: String) -> SymmetricKey? {
        guard let id = pageKeyID(at: photosDir.appendingPathComponent(filename)) else { return nil }
        return currentRing()[id]
    }

    func sealedInVaultFolder(pages filenames: [String]) -> Bool? {
        guard let vaultFolderID = (try? requireKeys().vaultFolder).map({ SealedEnvelope.keyID(of: $0) })
        else { return nil }
        var read = false
        for name in filenames {
            guard let id = pageKeyID(at: photosDir.appendingPathComponent(name)) else { continue }
            if id == vaultFolderID { return true }
            read = true
        }
        return read ? false : nil
    }

    private func pageKeyID(at url: URL) -> Data? {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? handle.close() }
        guard let head = try? handle.read(upToCount: SealedEnvelope.headerLength) else { return nil }
        return SealedEnvelope.keyID(in: head)
    }

    @discardableResult
    private func saveThumbnail(_ small: UIImage, for filename: String, key: SymmetricKey) -> Bool {
        guard let jpeg = small.jpegData(compressionQuality: 0.8) else { return false }
        do {
            let name = Self.thumbnailFilename(for: filename)
            let sealed = try seal(jpeg, name: name, key: key)
            let url = photosDir.appendingPathComponent(name)
            try sealed.write(to: url, options: [.atomic, .completeFileProtection])
            applyExclusion(url, true)
            return true
        } catch {
            return false
        }
    }

    func loadThumbnail(filename: String) -> UIImage? {
        let name = Self.thumbnailFilename(for: filename)
        let url = photosDir.appendingPathComponent(name)
        guard let raw = try? Data(contentsOf: url), let jpeg = try? open(raw, name: name) else { return nil }
        return ScanImage.decoded(jpeg, maxSide: ScanImage.thumbnailMaxSide)
    }

    func loadPhoto(filename: String) -> Result<UIImage, VaultFailure> {
        switch loadPhotoJPEG(filename: filename) {
        case .failure(let failure):
            return .failure(failure)
        case .success(let jpeg):
            guard let image = UIImage(data: jpeg) else {
                return .failure(.decryptFailed)
            }
            return .success(image)
        }
    }

    func loadPhotoJPEG(filename: String) -> Result<Data, VaultFailure> {
        let url = photosDir.appendingPathComponent(filename)
        guard let raw = try? Data(contentsOf: url) else {
            if FileManager.default.fileExists(atPath: url.path) {
                return .failure(.keychainWriteFailed)
            }
            return .failure(.missingFile)
        }
        do {
            let jpeg = try open(raw, name: filename)
            VaultIntegrity.noteMemoryDecrypt()
            return .success(jpeg)
        } catch StorageError.keyUnavailable {
            SafeMode.reportAtUse(.keyStorage)
            return .failure(.keychainWriteFailed)
        } catch {
            VaultIntegrity.noteSealRefused(subject: filename)
            return .failure(.decryptFailed)
        }
    }

    func sealedPhotoSize(filename: String) -> Int {
        let path = photosDir.appendingPathComponent(filename).path
        return (try? FileManager.default.attributesOfItem(atPath: path)[.size] as? Int) ?? 0
    }

    func sealedPhotoData(filename: String) -> Data? {
        let url = photosDir.appendingPathComponent(filename)
        return try? Data(contentsOf: url)
    }

    func sealForCloud(_ plaintext: Data, name: String) throws -> Data {
        try seal(plaintext, name: name, key: try requireKey())
    }

    func openFromCloud(_ sealed: Data, name: String) throws -> Data {
        _ = try requireKey()
        return try SealedEnvelope.open(sealed, ring: cloudRing(), name: name)
    }

    func cloudRingHolds(keyID: Data) -> Bool {
        cloudRing()[keyID] != nil
    }

    func copySealedPage(filename: String, to destination: URL,
                        attributes: [FileAttributeKey: Any]) throws -> (keyID: Data, size: Int) {
        let source = photosDir.appendingPathComponent(filename)
        let fm = FileManager.default
        if fm.fileExists(atPath: destination.path) { try fm.removeItem(at: destination) }
        try fm.copyItem(at: source, to: destination)
        try fm.setAttributes(attributes, ofItemAtPath: destination.path)
        guard let keyID = pageKeyID(at: destination) else { throw StorageError.sealFailed }
        let size = (try? fm.attributesOfItem(atPath: destination.path)[.size] as? Int) ?? 0
        return (keyID, size)
    }

    func storeSealedPage(_ sealed: Data, filename: String) throws {
        let url = photosDir.appendingPathComponent(filename)
        guard FileManager.default.fileExists(atPath: url.path) == false else {
            throw StorageError.nameTaken
        }
        try VaultRoom.write(sealed, to: url)
        applyExclusion(url, true)
    }

    func resealForNewName(_ sealed: Data, from oldName: String, to newName: String) throws -> Data {
        guard let id = SealedEnvelope.keyID(in: sealed), let key = currentRing()[id] else {
            throw StorageError.keyUnavailable
        }
        let plain = try SealedEnvelope.open(sealed, key: key, name: oldName)
        return try SealedEnvelope.seal(plain, key: key, name: newName)
    }

    func pageFileExists(filename: String) -> Bool {
        FileManager.default.fileExists(atPath: photosDir.appendingPathComponent(filename).path)
    }

    func wrappedKeys(under wrapping: SymmetricKey, includingVaultFolder: Bool) throws -> [String: Data] {
        let local = try requireKeys()
        var keys = cloudRing()
        keys[SealedEnvelope.keyID(of: local.tab)] = local.tab
        if includingVaultFolder { keys[SealedEnvelope.keyID(of: local.vaultFolder)] = local.vaultFolder }
        var out: [String: Data] = [:]
        for (id, one) in keys {
            out[SealedEnvelope.hex(id)] = try Self.wrap(one, under: wrapping)
        }
        return out
    }

    private static func wrap(_ key: SymmetricKey, under wrapping: SymmetricKey) throws -> Data {
        let raw = key.withUnsafeBytes { Data($0) }
        let box = try AES.GCM.seal(raw, using: wrapping)
        guard let combined = box.combined else { throw StorageError.sealFailed }
        return combined
    }

    static func unwrapMasterKey(_ wrapped: Data, under wrapping: SymmetricKey) throws -> SymmetricKey {
        let box = try AES.GCM.SealedBox(combined: wrapped)
        let raw = try AES.GCM.open(box, using: wrapping)
        return SymmetricKey(data: raw)
    }

    func sealForWire(_ data: Data, name: String) throws -> Data {
        try seal(data, name: name, key: try requireKey())
    }

    func saveIndex(_ plaintext: Data) throws {
        let sealed = try seal(plaintext, name: metaURL.lastPathComponent)
        try VaultRoom.write(sealed, to: metaURL)
        applyExclusion(metaURL, true)
    }

    enum CatalogRead {
        case absent
        case loaded(Data)
        case unreadable
    }

    func loadIndex() -> CatalogRead {
        guard FileManager.default.fileExists(atPath: metaURL.path) else { return .absent }
        guard let raw = try? Data(contentsOf: metaURL) else { return .unreadable }
        guard let plain = try? open(raw, name: metaURL.lastPathComponent) else {
            VaultLog.failure(.decryptFailed, detail: "vault.enc")
            return .unreadable
        }
        return .loaded(plain)
    }

    private func seal(_ plaintext: Data, name: String) throws -> Data {
        try seal(plaintext, name: name, key: try requireKey())
    }

    private func seal(_ plaintext: Data, name: String, key: SymmetricKey) throws -> Data {
        try SealedEnvelope.seal(plaintext, key: key, name: name)
    }

    private func open(_ sealed: Data, name: String) throws -> Data {
        ringLock.lock()
        let held = loadedKeysLocked() != nil
        let ring = self.ring
        ringLock.unlock()
        guard held else { throw StorageError.keyUnavailable }
        return try SealedEnvelope.open(sealed, ring: ring, name: name)
    }

    private func requireKey() throws -> SymmetricKey {
        try requireKeys().tab
    }

    private func keyFor(inVaultFolder: Bool) throws -> SymmetricKey {
        let keys = try requireKeys()
        return inVaultFolder ? keys.vaultFolder : keys.tab
    }

    private static let service = Bundle.main.bundleIdentifier ?? "Zirkon.ScanLocker"
    private static let account = "scanlocker.aes.v1"

    static let vaultFolderSlot = EnclaveKeyWrap.Slot(
        service: service,
        wrappedAccount: "scanlocker.aes.staybox.wrapped.v1",
        rawAccount: "scanlocker.aes.staybox.raw.v1",
        privateKeyAccount: "scanlocker.se.staybox.v1",
        label: "scanlocker.scan.staybox.wrap.v1"
    )

    private static func loadOrCreateVaultFolderKey() -> SymmetricKey? {
        do {
            return try EnclaveKeyWrap.loadOrCreate(in: vaultFolderSlot).key
        } catch {
            VaultLog.failure(.keychainWriteFailed, detail: "Scan Vault key unavailable; not replaced")
            return nil
        }
    }

    private static func loadOrCreateKey() -> SymmetricKey? {
        switch readKey() {
        case .found(let data):
            return SymmetricKey(data: data)
        case .unavailable:
            VaultLog.failure(.keychainWriteFailed, detail: "AES key unreadable; not replaced")
            return nil
        case .notFound:
            break
        }
        let key = KeyTwin.twinToAdopt(for: .scan) ?? SymmetricKey(size: .bits256)
        guard saveKey(key) else {
            VaultLog.failure(.keychainWriteFailed, detail: "new AES key not stored")
            return loadKey()
        }
        guard let stored = loadKey() else {
            deleteKey()
            VaultLog.failure(.keychainWriteFailed, detail: "new AES key not readable after write")
            return nil
        }
        return stored
    }

    private static func readKey() -> KeychainGeneric.Read {
        KeychainGeneric.read(service: service, account: account)
    }

    private static func loadKey() -> SymmetricKey? {
        guard let data = KeychainGeneric.get(service: service, account: account) else { return nil }
        return SymmetricKey(data: data)
    }

    @discardableResult
    private static func saveKey(_ key: SymmetricKey) -> Bool {
        let data = key.withUnsafeBytes { Data($0) }
        if KeychainGeneric.addOnly(service: service, account: account, data: data) { return true }
        if loadKey() != nil { return true }
        VaultLog.failure(.keychainWriteFailed, detail: "tab key not added")
        return false
    }

    static func keyIsPresent() -> Bool { loadKey() != nil }

    private static func deleteKey() {
        KeychainGeneric.delete(service: service, account: account)
    }

    struct BackupExclusion {
        let read: Int
        let excluded: Int

        var verified: Bool { read > 0 && read == excluded }
    }

    func backupExclusion() -> BackupExclusion {
        let urls = [rootURL, photosDir, metaURL, lockerURL, Self.trustedIndexURL,
                    Self.auditIndexURL,
                    ShareOutbox.directoryURL, CloudOutbox.directoryURL]
        var read = 0
        var excluded = 0
        for url in urls {
            guard FileManager.default.fileExists(atPath: url.path) else { continue }
            guard let values = try? url.resourceValues(forKeys: [.isExcludedFromBackupKey]),
                  let flag = values.isExcludedFromBackup else { continue }
            read += 1
            if flag { excluded += 1 }
        }
        return BackupExclusion(read: read, excluded: excluded)
    }

    func backupIsExcluded() -> Bool { backupExclusion().verified }

    struct VaultKeyReport {
        var opened = 0
        var refused = 0
        var keyLoaded = true
        var finished = true

        var verified: Bool { keyLoaded && finished && refused == 0 }
    }

    func vaultKeyReport(filenames: [String], deadline: Date) -> VaultKeyReport {
        var report = VaultKeyReport()
        guard let key = try? requireKeys().vaultFolder else {
            report.keyLoaded = false
            return report
        }
        for filename in filenames {
            guard Date() < deadline else {
                report.finished = false
                return report
            }
            let url = photosDir.appendingPathComponent(filename)
            guard FileManager.default.fileExists(atPath: url.path) else { continue }
            let opened = autoreleasepool { () -> Bool in
                guard let sealed = try? Data(contentsOf: url) else { return false }
                return (try? SealedEnvelope.open(sealed, key: key, name: filename)) != nil
            }
            if opened { report.opened += 1 } else { report.refused += 1 }
        }
        return report
    }

    func writeLockerIndex(_ sealed: Data) throws {
        try VaultRoom.write(sealed, to: lockerURL)
        applyExclusion(lockerURL, true)
    }

    func readLockerIndex() -> CatalogRead {
        guard FileManager.default.fileExists(atPath: lockerURL.path) else { return .absent }
        guard let raw = try? Data(contentsOf: lockerURL) else { return .unreadable }
        return .loaded(raw)
    }

    static var lockerIndexName: String { lockerIndexURL.lastPathComponent }

    func saveAuditIndex(_ plaintext: Data) throws {
        let url = Self.auditIndexURL
        let sealed = try seal(plaintext, name: url.lastPathComponent)
        try VaultRoom.write(sealed, to: url)
        applyExclusion(url, true)
    }

    func loadAuditIndex() -> CatalogRead {
        let url = Self.auditIndexURL
        guard FileManager.default.fileExists(atPath: url.path) else { return .absent }
        guard let raw = try? Data(contentsOf: url) else { return .unreadable }
        guard let plain = try? open(raw, name: url.lastPathComponent) else {
            VaultLog.failure(.decryptFailed, detail: "audit.enc")
            return .unreadable
        }
        return .loaded(plain)
    }

    func saveTrustedIndex(_ plaintext: Data) throws {
        let url = Self.trustedIndexURL
        let sealed = try seal(plaintext, name: url.lastPathComponent)
        try VaultRoom.write(sealed, to: url)
        applyExclusion(url, true)
    }

    func removeTrustedIndex() {
        try? FileManager.default.removeItem(at: Self.trustedIndexURL)
    }

    func loadTrustedIndex() -> CatalogRead {
        let url = Self.trustedIndexURL
        guard FileManager.default.fileExists(atPath: url.path) else { return .absent }
        guard let raw = try? Data(contentsOf: url) else { return .unreadable }
        guard let plain = try? open(raw, name: url.lastPathComponent) else {
            VaultLog.failure(.decryptFailed, detail: "trusted.enc")
            return .unreadable
        }
        return .loaded(plain)
    }

    func sweepOrphanPhotos(keeping referenced: Set<String>) {
        guard FileManager.default.fileExists(atPath: Self.vaultIndexURL.path) else { return }
        guard let files = try? FileManager.default.contentsOfDirectory(
            at: photosDir, includingPropertiesForKeys: nil
        ) else { return }
        var keep = referenced
        for name in referenced { keep.insert(Self.thumbnailFilename(for: name)) }
        for url in files where keep.contains(url.lastPathComponent) == false {
            guard Self.isSweepablePhotoFile(url.lastPathComponent) else { continue }
            try? FileManager.default.removeItem(at: url)
        }
    }

    struct StrandedPage {
        let filename: String
        let inVaultFolder: Bool
        let createdAt: Date
    }

    struct StrandedSweep {
        let pages: [StrandedPage]
        let unreached: Int
        let deadlineFired: Bool
    }

    func strandedPages(until deadline: Date) -> StrandedSweep {
        guard let files = try? FileManager.default.contentsOfDirectory(
            at: photosDir, includingPropertiesForKeys: [.contentModificationDateKey]
        ) else { return StrandedSweep(pages: [], unreached: 0, deadlineFired: false) }
        let ring = currentRing()
        let vaultFolderID = (try? requireKeys().vaultFolder).map { SealedEnvelope.keyID(of: $0) }
        var found: [StrandedPage] = []
        var unreached = 0
        var fired = false
        for url in files.sorted(by: { $0.lastPathComponent < $1.lastPathComponent }) {
            guard Date() < deadline else { fired = true; break }
            let name = url.lastPathComponent
            guard Self.isSweepablePhotoFile(name), name.hasPrefix("t-") == false else { continue }
            guard let id = pageKeyID(at: url), ring[id] != nil else {
                unreached += 1
                continue
            }
            let written = (try? url.resourceValues(forKeys: [.contentModificationDateKey]))?
                .contentModificationDate ?? Date()
            found.append(StrandedPage(filename: name,
                                      inVaultFolder: id == vaultFolderID,
                                      createdAt: written))
        }
        return StrandedSweep(pages: found, unreached: unreached, deadlineFired: fired)
    }

    static func isSweepablePhotoFile(_ name: String) -> Bool {
        guard name.hasSuffix(".enc") else { return false }
        var stem = String(name.dropLast(4))
        if stem.hasPrefix("t-") { stem = String(stem.dropFirst(2)) }
        return UUID(uuidString: stem) != nil
    }

    static let stagingPrefix = "staging-"

    private func stagingURL(_ id: UUID) -> URL {
        rootURL.appendingPathComponent(Self.stagingPrefix + id.uuidString + ".enc")
    }

    func saveStagingManifest(_ plaintext: Data, id: UUID) {
        let url = stagingURL(id)
        guard let sealed = try? seal(plaintext, name: url.lastPathComponent) else { return }
        try? VaultRoom.write(sealed, to: url)
        applyExclusion(url, true)
    }

    func removeStagingManifest(id: UUID) {
        try? FileManager.default.removeItem(at: stagingURL(id))
    }

    func loadStagingManifests() -> [(id: UUID, plaintext: Data)] {
        guard let files = try? FileManager.default.contentsOfDirectory(
            at: rootURL, includingPropertiesForKeys: nil
        ) else { return [] }
        var found: [(UUID, Data)] = []
        for url in files {
            let name = url.lastPathComponent
            guard name.hasPrefix(Self.stagingPrefix), name.hasSuffix(".enc") else { continue }
            let core = name.dropFirst(Self.stagingPrefix.count).dropLast(4)
            guard let id = UUID(uuidString: String(core)) else { continue }
            guard let raw = try? Data(contentsOf: url), let plain = try? open(raw, name: name) else {
                VaultLog.failure(.decryptFailed, detail: name)
                continue
            }
            found.append((id, plain))
        }
        return found
    }

    func excludeFromBackup() {
        applyExclusion(rootURL, true)
        applyExclusion(photosDir, true)
        applyExclusion(metaURL, true)
        applyExclusion(lockerURL, true)
        applyExclusion(Self.trustedIndexURL, true)
        applyExclusion(Self.auditIndexURL, true)
    }

    func excludePhotoFilesFromBackupInBackground() {
        let photosDir = self.photosDir
        DispatchQueue.global(qos: .utility).async { [self] in
            guard let files = try? FileManager.default.contentsOfDirectory(
                at: photosDir, includingPropertiesForKeys: nil
            ) else { return }
            files.forEach { applyExclusion($0, true) }
        }
    }

    private func applyExclusion(_ url: URL, _ excluded: Bool) {
        guard FileManager.default.fileExists(atPath: url.path) else { return }
        var values = URLResourceValues()
        values.isExcludedFromBackup = excluded
        var mutable = url
        try? mutable.setResourceValues(values)
    }

    enum StorageError: Error {
        case sealFailed
        case keyUnavailable
        case nameTaken
    }
}

extension Notification.Name {
    static let vaultSealRefused = Notification.Name("vault.sealRefused")
    static let vaultMemoryDecrypt = Notification.Name("vault.memoryDecrypt")
}
