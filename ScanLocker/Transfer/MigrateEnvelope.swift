//
//  MigrateEnvelope.swift
//  ScanLocker
//
//  A transfer as it travels: one picture, one Locker item, the envelope that
//  holds them and what comes back when one cannot be read.
//

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
    var sealed: Data
    var origin: PhotoOrigin
    var extraSealed: [Data]
    /// The name each extra page was sealed under on the sending device, in
    /// the order of `extraSealed`. Every page is bound to its own file name
    /// as authenticated data, so the receiver needs the name to open the
    /// page before it reseals it under a name of its own. The first page's
    /// name is `filename`. A picture from a build that wrote no names
    /// cannot be opened here and is refused with its name.
    var extraFilenames: [String]
    /// True when this picture was in Vault on the sending device, so the
    /// receiver files it in its own Vault. Without it a picture sent one
    /// at a time would land in Home and be shareable from there: send to a
    /// paired device, receive, share. Older builds neither write nor read
    /// the field, and a picture arriving without it is treated as not from
    /// Vault, which is what it was.
    var fromStayBox: Bool?

    enum CodingKeys: String, CodingKey {
        case id, folderId, name, capturedAt, isSecure, filename, sealed, origin, extraSealed
        case extraFilenames
        /// Spelled as the folder is named. An earlier build wrote this flag
        /// under one of the folder's two earlier names, and this build reads
        /// neither, so both devices take this build before a Vault picture
        /// is sent between them.
        case fromStayBox
    }

    init(id: UUID, folderId: UUID, name: String, capturedAt: Date, isSecure: Bool,
         filename: String, sealed: Data, origin: PhotoOrigin, extraSealed: [Data],
         extraFilenames: [String] = [], fromStayBox: Bool? = nil) {
        self.extraFilenames = extraFilenames
        self.fromStayBox = fromStayBox
        self.id = id
        self.folderId = folderId
        self.name = name
        self.capturedAt = capturedAt
        self.isSecure = isSecure
        self.filename = filename
        self.sealed = sealed
        self.origin = origin
        self.extraSealed = extraSealed
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(UUID.self, forKey: .id)
        folderId = try c.decode(UUID.self, forKey: .folderId)
        name = try c.decode(String.self, forKey: .name)
        capturedAt = try c.decode(Date.self, forKey: .capturedAt)
        isSecure = try c.decode(Bool.self, forKey: .isSecure)
        filename = try c.decode(String.self, forKey: .filename)
        sealed = try c.decode(Data.self, forKey: .sealed)
        origin = try c.decodeIfPresent(PhotoOrigin.self, forKey: .origin) ?? .captured
        extraSealed = try c.decodeIfPresent([Data].self, forKey: .extraSealed) ?? []
        extraFilenames = try c.decodeIfPresent([String].self, forKey: .extraFilenames) ?? []
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
    /// True when this item was in Vault on the sending device, so the
    /// receiver files it in its own Vault. A single item send carries no
    /// folders at all, so without this the item would land in Home and be
    /// shareable from there: send to a paired device, receive, share. Older
    /// builds neither write nor read the field, and an item arriving without
    /// it is treated as not from Vault, which is what it was.
    var fromStayBox: Bool?
}

struct MigrateEnvelope: Codable {
    var salt: Data
    /// Every Scan key a blob in the envelope may be sealed under, each
    /// wrapped for the one paired device and named by its identifier in
    /// hex: the sender's tab key, every key it holds for restored material,
    /// and its Vault key when a Vault page travels. A page travels byte
    /// for byte as it sits on the sender, a Locker payload is sealed under
    /// the tab key with its identifier as the name, and the receiver opens
    /// each under the key its own header names. Over the local link and
    /// never the internet.
    var wrappedKeys: [String: Data]
    var folders: [ScanFolder]
    var photos: [MigratePhoto]
    var selectedFolderID: UUID
    var lockerFolders: [ScanFolder]
    var lockerItems: [MigrateLockerItem]
    var itemShare: Bool

    enum CodingKeys: String, CodingKey {
        case salt, wrappedKeys, folders, photos, selectedFolderID, lockerFolders, lockerItems, itemShare
    }

    init(
        salt: Data,
        wrappedKeys: [String: Data],
        folders: [ScanFolder],
        photos: [MigratePhoto],
        selectedFolderID: UUID,
        lockerFolders: [ScanFolder] = [],
        lockerItems: [MigrateLockerItem] = [],
        itemShare: Bool = false
    ) {
        self.salt = salt
        self.wrappedKeys = wrappedKeys
        self.folders = folders
        self.photos = photos
        self.selectedFolderID = selectedFolderID
        self.lockerFolders = lockerFolders
        self.lockerItems = lockerItems
        self.itemShare = itemShare
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        salt = try c.decode(Data.self, forKey: .salt)
        wrappedKeys = try c.decode([String: Data].self, forKey: .wrappedKeys)
        folders = try c.decode([ScanFolder].self, forKey: .folders)
        photos = try c.decode([MigratePhoto].self, forKey: .photos)
        selectedFolderID = try c.decode(UUID.self, forKey: .selectedFolderID)
        lockerFolders = try c.decodeIfPresent([ScanFolder].self, forKey: .lockerFolders) ?? []
        lockerItems = try c.decodeIfPresent([MigrateLockerItem].self, forKey: .lockerItems) ?? []
        itemShare = try c.decodeIfPresent(Bool.self, forKey: .itemShare) ?? false
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(salt, forKey: .salt)
        try c.encode(wrappedKeys, forKey: .wrappedKeys)
        try c.encode(folders, forKey: .folders)
        try c.encode(photos, forKey: .photos)
        try c.encode(selectedFolderID, forKey: .selectedFolderID)
        try c.encode(lockerFolders, forKey: .lockerFolders)
        try c.encode(lockerItems, forKey: .lockerItems)
        try c.encode(itemShare, forKey: .itemShare)
    }
}

struct MigrateImportResult {
    var photoCount: Int
    var lockerCount: Int
    var itemShare: Bool
}

enum VaultMigrateError: LocalizedError {
    case nothingToSend
    case couldNotPack(String)
    /// The chosen contents come to more than one transfer carries.
    case overCeiling(bytes: Int)
    /// The bytes arrived but are not a ScanLocker transfer.
    case payloadUnreadable
    /// The envelope is fine; this iPhone's key for the sending device did
    /// not open it.
    case keyRejected
    case pictureFailed(name: String, reason: String)
    case lockerItemFailed(title: String, reason: String)
    /// A catalog write after the receive failed and everything that arrived
    /// was taken back off this device.
    case nothingKept
    /// The pictures were entered, the Locker write then failed, and the
    /// write that would have taken the pictures back out failed too.
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
    /// The catalog record this staged picture becomes, in the given folder.
    ///
    /// A picture the sender had in Vault takes the received origin and the
    /// moment of the arrival, so it wears the yellow mark here and its alert
    /// names when it came. Every other picture keeps the origin the sender
    /// sent, a copy restored from iCloud included, since that arrives with
    /// the flag unset. `arrivedAt` is one moment for the whole arrival.
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
