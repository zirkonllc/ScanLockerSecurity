# ScanLocker Security

ScanLocker is an iPhone vault made by Zirkon LLC. This repository publishes the ScanLocker source files that keep its keys, encrypt what it stores, pair two iPhones and encrypt a transfer between them. Each file stands here exactly as the app compiles it, and the app carries no third-party code.

More about ScanLocker is at [www.zirkon.services](https://www.zirkon.services).

## Key storage

| File | What it does |
| --- | --- |
| [`EnclaveKeyWrap.swift`](ScanLocker/Security/EnclaveKeyWrap.swift) | It keeps each 32-byte AES key wrapped under a P-256 key made inside the Secure Enclave, so the key opens only on the iPhone that made it. |
| [`SealedEnvelope.swift`](ScanLocker/Security/SealedEnvelope.swift) | It defines every encrypted blob the app stores: a format byte, a four-byte key identifier and an AES-256-GCM box bound to the blob's own name. |
| [`EncryptedVaultStorage.swift`](ScanLocker/Store/EncryptedVaultStorage.swift) | It reads and writes the encrypted blobs under the catalog. |
| [`LockerSeal.swift`](ScanLocker/Store/LockerSeal.swift) | It encrypts each Locker secret and holds the key that decrypts it while one item is on show. |

## Transfer encryption

| File | What it does |
| --- | --- |
| [`TrustedDeviceCrypto.swift`](ScanLocker/Transfer/Trusted/TrustedDeviceCrypto.swift) | It derives every key a paired device uses from one Curve25519 shared secret, each through HKDF under a label that names its one job. |
| [`TransferCrypto.swift`](ScanLocker/Transfer/TransferCrypto.swift) | It derives the keys a transfer is encrypted with and the PIN the two iPhones agree on. |
| [`MigrateEnvelope.swift`](ScanLocker/Transfer/MigrateEnvelope.swift) | It defines a transfer as it travels: each picture, each Locker item and the envelope that holds them. |
| [`TransferResume.swift`](ScanLocker/Transfer/TransferResume.swift) | It lets a transfer that lost its connection pick up where it stopped: the receiver names the next record it needs, under a key derived from the transfer's own session key, so no other device can move the sender's place. |

## Pairing

| File | What it does |
| --- | --- |
| [`TrustedDevicePairingLink.swift`](ScanLocker/Transfer/Trusted/TrustedDevicePairingLink.swift) | It runs the pairing handshake, in which a PIN shown on one iPhone and typed on the other authenticates the exchange of their public keys. |
| [`TrustedPairingCard.swift`](ScanLocker/Transfer/Trusted/TrustedPairingCard.swift) | It pairs two iPhones with no live connection: each shows a line of text holding its public key, sent by any messenger, and both show a check code for the two people to compare by voice before anything is saved. |
| [`Field25519.swift`](ScanLocker/Transfer/Trusted/Field25519.swift) | It computes in the field of integers modulo 2^255 − 19 and runs the Elligator 2 map that derives the generator of the CPace exchange. |
| [`TrustedPairingMarks.swift`](ScanLocker/Transfer/Trusted/TrustedPairingMarks.swift) | It draws the PIN and the steps on the pairing screens. |

© 2026 Zirkon LLC. All rights reserved.
