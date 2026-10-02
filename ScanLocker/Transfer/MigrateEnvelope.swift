import Combine
import CommonCrypto
import CryptoKit
import Darwin
import Foundation
import Network
import Security

struct MigratePhoto: Codable {
    var id: UUID
    var folderId: UUID
    var name: String
    var capturedAt: Date
    var isSecure: Bool
    var filename: String
    var origin: PhotoOrigin
    var extraFilenames: [String]
    var pageCount: Int
    var fromStayBox: Bool?

    enum CodingKeys: String, CodingKey {
        case id, folderId, name, capturedAt, isSecure, filename, origin
        case extraFilenames, pageCount
        case fromStayBox
    }

    init(id: UUID, folderId: UUID, name: String, capturedAt: Date, isSecure: Bool,
         filename: String, origin: PhotoOrigin, extraFilenames: [String] = [],
         pageCount: Int, fromStayBox: Bool? = nil) {
        self.extraFilenames = extraFilenames
        self.pageCount = pageCount
        self.fromStayBox = fromStayBox
        self.id = id
        self.folderId = folderId
        self.name = name
        self.capturedAt = capturedAt
        self.isSecure = isSecure
        self.filename = filename
        self.origin = origin
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(UUID.self, forKey: .id)
        folderId = try c.decode(UUID.self, forKey: .folderId)
        name = try c.decode(String.self, forKey: .name)
        capturedAt = try c.decode(Date.self, forKey: .capturedAt)
        isSecure = try c.decode(Bool.self, forKey: .isSecure)
        filename = try c.decode(String.self, forKey: .filename)
        origin = try c.decodeIfPresent(PhotoOrigin.self, forKey: .origin) ?? .captured
        extraFilenames = try c.decodeIfPresent([String].self, forKey: .extraFilenames) ?? []
        pageCount = try c.decode(Int.self, forKey: .pageCount)
        fromStayBox = try c.decodeIfPresent(Bool.self, forKey: .fromStayBox)
    }
}

struct MigrateLockerItem: Codable {
    var id: UUID
    var kind: LockerKind
    var title: String
    var createdAt: Date
    var seedStyle: SeedStyle?
    var sealed: Data
    var folderId: UUID?
    var isSecure: Bool?
    var origin: PhotoOrigin?
    var fromStayBox: Bool?
}

struct MigrateEnvelope: Codable {
    var salt: Data
    var wrappedKeys: [String: Data]
    var folders: [ScanFolder]
    var selectedFolderID: UUID
    var lockerFolders: [ScanFolder]
    var itemShare: Bool
    var pictureCount: Int
    var pageCount: Int
    var lockerCount: Int
    var byteTotal: Int

    enum CodingKeys: String, CodingKey {
        case salt, wrappedKeys, folders, selectedFolderID, lockerFolders, itemShare
        case pictureCount, pageCount, lockerCount, byteTotal
    }

    init(
        salt: Data,
        wrappedKeys: [String: Data],
        folders: [ScanFolder],
        selectedFolderID: UUID,
        lockerFolders: [ScanFolder] = [],
        itemShare: Bool = false,
        pictureCount: Int,
        pageCount: Int,
        lockerCount: Int,
        byteTotal: Int
    ) {
        self.salt = salt
        self.wrappedKeys = wrappedKeys
        self.folders = folders
        self.selectedFolderID = selectedFolderID
        self.lockerFolders = lockerFolders
        self.itemShare = itemShare
        self.pictureCount = pictureCount
        self.pageCount = pageCount
        self.lockerCount = lockerCount
        self.byteTotal = byteTotal
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        salt = try c.decode(Data.self, forKey: .salt)
        wrappedKeys = try c.decode([String: Data].self, forKey: .wrappedKeys)
        folders = try c.decode([ScanFolder].self, forKey: .folders)
        selectedFolderID = try c.decode(UUID.self, forKey: .selectedFolderID)
        lockerFolders = try c.decodeIfPresent([ScanFolder].self, forKey: .lockerFolders) ?? []
        itemShare = try c.decodeIfPresent(Bool.self, forKey: .itemShare) ?? false
        pictureCount = try c.decode(Int.self, forKey: .pictureCount)
        pageCount = try c.decode(Int.self, forKey: .pageCount)
        lockerCount = try c.decode(Int.self, forKey: .lockerCount)
        byteTotal = try c.decode(Int.self, forKey: .byteTotal)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(salt, forKey: .salt)
        try c.encode(wrappedKeys, forKey: .wrappedKeys)
        try c.encode(folders, forKey: .folders)
        try c.encode(selectedFolderID, forKey: .selectedFolderID)
        try c.encode(lockerFolders, forKey: .lockerFolders)
        try c.encode(itemShare, forKey: .itemShare)
        try c.encode(pictureCount, forKey: .pictureCount)
        try c.encode(pageCount, forKey: .pageCount)
        try c.encode(lockerCount, forKey: .lockerCount)
        try c.encode(byteTotal, forKey: .byteTotal)
    }
}

struct MigrateEnd: Codable {
    var recordCount: Int
    var pictureCount: Int
    var pageCount: Int
    var lockerCount: Int
}

struct MigrateImportResult {
    var photoCount: Int
    var lockerCount: Int
    var itemShare: Bool
}

enum VaultMigrateError: LocalizedError {
    case nothingToSend
    case couldNotPack(String)
    case overCeiling(bytes: Int)
    case payloadUnreadable
    case keyRejected
    case pictureFailed(name: String, reason: String)
    case lockerItemFailed(title: String, reason: String)
    case nothingKept
    case picturesKeptOnly

    var errorDescription: String? {
        switch self {
        case .nothingToSend:
            return "There is nothing to send."
        case .overCeiling(let bytes):
            let size = ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .file)
            return "A transfer carries up to \(MigrateSource.ceilingName), and this one comes to about \(size), so nothing was sent. Send it in parts of \(MigrateSource.ceilingName) or less, as shares from Scan and Locker for example."
        case .couldNotPack(let reason):
            return "This mobile device could not prepare the transfer. \(reason)"
        case .payloadUnreadable:
            return "What arrived is not a ScanLocker transfer, or it did not arrive in one piece. Start the transfer again on both devices."
        case .keyRejected:
            return "Nothing was received. These two devices no longer recognise each other. Remove each under Paired Devices on both, pair them again and start the transfer."
        case .pictureFailed(let name, let reason):
            return "A picture named \(name) could not be saved on this device. \(reason)"
        case .lockerItemFailed(let title, let reason):
            return "A locker item named \(title) could not be saved on this device. \(reason)"
        case .nothingKept:
            return "Nothing that arrived was kept. Start the transfer again on both devices."
        case .picturesKeptOnly:
            return "The pictures that arrived were kept. The locker items were not. Start the transfer again on both devices and send the locker items."
        }
    }
}

extension VaultStore.MigrateArrival.StagedPhoto {
    func record(in folderId: UUID, arrivedAt: Date) -> VaultPhoto {
        VaultPhoto(id: id,
                   folderId: folderId,
                   name: name,
                   capturedAt: capturedAt,
                   isSecure: isSecure,
                   filename: filename,
                   origin: fromStayBox ? .received : origin,
                   extraFilenames: extraFilenames,
                   arrivedAt: fromStayBox ? arrivedAt : nil)
    }
}
