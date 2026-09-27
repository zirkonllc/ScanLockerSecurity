//
//  Field25519.swift
//  ScanLocker
//
//  ================= WHAT THIS FILE IS =================
//  Arithmetic in the field of integers modulo 2^255 - 19 and the
//  Elligator 2 map from a field element to a point on Curve25519. The
//  trusted-device pairing derives the generator of its CPace exchange
//  through the map once per pairing. Nothing else in the app reads this
//  file.
//
//  ================= WHERE IT COMES FROM =================
//  RFC 9380 gives the map in section 6.7.1 and its straight-line form in
//  appendix F.3, the square root for this field in appendix I.2 and
//  is_square, sgn0 and inv0 in section 4. The curve constants are those of
//  its section 8.5: J = 486662, K = 1 and Z = 2. The CPace draft repeats
//  the decoding of a u coordinate in its appendix A.4.
//
//  ================= HOW IT IS WRITTEN =================
//  It is written plainly, with no performance work. A value is eight little-endian limbs
//  of 32 bits, a product is schoolbook, an exponentiation is square and
//  multiply and reduction leans on 2^255 being 19 in this field. The map
//  costs a few milliseconds and runs once per pairing on the owner's own
//  phone. The build proves every function against the published vectors in
//  StressTests/PairingVectors.swift. The link proves one vector again
//  before the first pairing after each launch, so a wrong answer on some
//  future chip refuses to pair and no key is derived from it.
//

import Foundation

/// `nonisolated`, like `TrustedDeviceCrypto`: the map runs wherever the
/// caller runs and this project's default isolation is the main actor.
nonisolated enum Field25519 {

    // MARK: - The field

    /// 2^255 - 19, as eight little-endian limbs of 32 bits. Every other
    /// constant below is computed from this one, so it is the one to get
    /// right.
    static let p: [UInt32] = [0xFFFF_FFED] + Array(repeating: 0xFFFF_FFFF, count: 6) + [0x7FFF_FFFF]

    /// An element of the field, always held reduced below p.
    struct Element: Equatable {
        /// Eight little-endian limbs of 32 bits.
        fileprivate let limbs: [UInt32]

        fileprivate init(reduced limbs: [UInt32]) {
            self.limbs = limbs
        }

        init(_ small: UInt32) {
            limbs = Field25519.pad([small], to: 8)
        }

        /// Thirty-two little-endian bytes, the encoding RFC 7748 uses. A
        /// value at or above p is reduced into the field.
        init?(littleEndian bytes: Data) {
            guard bytes.count == 32 else { return nil }
            var limbs = [UInt32](repeating: 0, count: 8)
            for (index, byte) in bytes.enumerated() {
                limbs[index / 4] |= UInt32(byte) << (8 * UInt32(index % 4))
            }
            self.limbs = Field25519.reduce(limbs)
        }

        var littleEndian: Data {
            var bytes = [UInt8](repeating: 0, count: 32)
            for index in 0..<32 {
                bytes[index] = UInt8((limbs[index / 4] >> (8 * UInt32(index % 4))) & 0xFF)
            }
            return Data(bytes)
        }

        /// RFC 9380 section 4.1 for a prime field: the low bit.
        var sgn0: UInt32 { limbs[0] & 1 }
    }

    static let zero = Element(0)
    static let one = Element(1)

    // MARK: - Field operations

    static func add(_ a: Element, _ b: Element) -> Element {
        Element(reduced: reduce(rawAdd(a.limbs, b.limbs)))
    }

    /// a - b. When a is the smaller, p is added to it first, so the raw
    /// subtraction never borrows past the top limb.
    static func subtract(_ a: Element, _ b: Element) -> Element {
        let lifted = compare(a.limbs, b.limbs) >= 0 ? a.limbs : rawAdd(a.limbs, p)
        return Element(reduced: reduce(rawSubtract(lifted, b.limbs)))
    }

    static func negate(_ a: Element) -> Element {
        subtract(zero, a)
    }

    static func multiply(_ a: Element, _ b: Element) -> Element {
        Element(reduced: reduce(rawMultiply(a.limbs, b.limbs)))
    }

    static func square(_ a: Element) -> Element {
        multiply(a, a)
    }

    /// Square and multiply over every bit of the exponent, highest first.
    /// The exponent is a plain integer in little-endian limbs.
    static func power(_ base: Element, _ exponent: [UInt32]) -> Element {
        var result = one
        for bit in stride(from: exponent.count * 32 - 1, through: 0, by: -1) {
            result = square(result)
            if (exponent[bit / 32] >> UInt32(bit % 32)) & 1 == 1 {
                result = multiply(result, base)
            }
        }
        return result
    }

    /// x^(p - 2), which is 1 / x and 0 for x = 0: the inv0 of RFC 9380.
    static func invert(_ x: Element) -> Element {
        power(x, pMinus2)
    }

    /// x^((p - 1) / 2) is 0 or 1 exactly when x is a square.
    static func isSquare(_ x: Element) -> Bool {
        let symbol = power(x, legendreExponent)
        return symbol == zero || symbol == one
    }

    /// RFC 9380 appendix I.2, for a field whose order is 5 modulo 8. The
    /// answer squares back to x only when x is a square, which is all the
    /// map ever asks of it.
    static func squareRoot(_ x: Element) -> Element {
        let tv1 = power(x, sqrtExponent)
        let tv2 = multiply(tv1, sqrtMinusOne)
        return square(tv1) == x ? tv1 : tv2
    }

    /// p - 2, (p - 1) / 2, (p + 3) / 8 and (p - 1) / 4, each computed from p.
    static let pMinus2 = trim(rawSubtract(p, [2]))
    static let legendreExponent = trim(shiftRight(rawSubtract(p, [1]), by: 1))
    static let sqrtExponent = trim(shiftRight(rawAdd(p, [3]), by: 3))
    /// sqrt(-1). Two is not a square in this field, so 2^((p - 1) / 4)
    /// squares to -1.
    static let sqrtMinusOne = power(Element(2), trim(shiftRight(rawSubtract(p, [1]), by: 2)))

    // MARK: - Elligator 2

    /// Curve25519 as the Montgomery curve K * t^2 = s^3 + J * s^2 + s, and
    /// the non-square Z that RFC 9380 section 8.5 fixes for it.
    static let J = Element(486662)
    static let K = one
    static let Z = Element(2)
    private static let c1 = multiply(J, invert(K))
    private static let c2 = invert(square(K))
    private static let minusOne = negate(one)
    private static let minusC1 = negate(c1)

    /// map_to_curve_elligator2 of RFC 9380 section 6.7.1, step for step in
    /// the straight-line form of its appendix F.3: (s, t) on Curve25519 for
    /// any field element u. CPace keeps s and discards t.
    static func elligator2(_ u: Element) -> (s: Element, t: Element) {
        var tv1 = square(u)
        tv1 = multiply(Z, tv1)                    // Z * u^2
        let e1 = tv1 == minusOne                  // exceptional case: Z * u^2 == -1
        tv1 = e1 ? zero : tv1
        var x1 = add(tv1, one)
        x1 = invert(x1)
        x1 = multiply(minusC1, x1)                // -(J / K) / (1 + Z * u^2)
        var gx1 = add(x1, c1)
        gx1 = multiply(gx1, x1)
        gx1 = add(gx1, c2)
        gx1 = multiply(gx1, x1)                   // x1^3 + (J / K) * x1^2 + x1 / K^2
        let x2 = subtract(negate(x1), c1)
        let gx2 = multiply(tv1, gx1)
        let e2 = isSquare(gx1)
        let x = e2 ? x1 : x2
        let y2 = e2 ? gx1 : gx2
        var y = squareRoot(y2)
        let e3 = y.sgn0 == 1
        if e2 != e3 { y = negate(y) }             // fix the sign of y
        return (multiply(x, K), multiply(y, K))
    }

    // MARK: - Plain multi-limb integers

    /// These work on little-endian limbs of 32 bits of any length. None of
    /// them is clever.

    fileprivate static func pad(_ a: [UInt32], to count: Int) -> [UInt32] {
        a.count >= count ? a : a + Array(repeating: 0, count: count - a.count)
    }

    /// Drops high zero limbs, keeping at least one.
    fileprivate static func trim(_ a: [UInt32]) -> [UInt32] {
        guard !a.isEmpty else { return [0] }
        var trimmed = a
        while trimmed.count > 1, trimmed[trimmed.count - 1] == 0 {
            trimmed.removeLast()
        }
        return trimmed
    }

    fileprivate static func compare(_ a: [UInt32], _ b: [UInt32]) -> Int {
        let x = trim(a), y = trim(b)
        if x.count != y.count { return x.count < y.count ? -1 : 1 }
        for index in stride(from: x.count - 1, through: 0, by: -1) where x[index] != y[index] {
            return x[index] < y[index] ? -1 : 1
        }
        return 0
    }

    fileprivate static func rawAdd(_ a: [UInt32], _ b: [UInt32]) -> [UInt32] {
        let count = max(a.count, b.count)
        let x = pad(a, to: count), y = pad(b, to: count)
        var out = [UInt32](repeating: 0, count: count + 1)
        var carry: UInt64 = 0
        for index in 0..<count {
            let sum = UInt64(x[index]) + UInt64(y[index]) + carry
            out[index] = UInt32(truncatingIfNeeded: sum)
            carry = sum >> 32
        }
        out[count] = UInt32(carry)
        return out
    }

    /// a - b, for a at least b. Every caller lifts or compares first.
    fileprivate static func rawSubtract(_ a: [UInt32], _ b: [UInt32]) -> [UInt32] {
        let count = max(a.count, b.count)
        let x = pad(a, to: count), y = pad(b, to: count)
        var out = [UInt32](repeating: 0, count: count)
        var borrow: Int64 = 0
        for index in 0..<count {
            var difference = Int64(x[index]) - Int64(y[index]) - borrow
            if difference < 0 {
                difference += Int64(1) << 32
                borrow = 1
            } else {
                borrow = 0
            }
            out[index] = UInt32(difference)
        }
        return out
    }

    fileprivate static func rawMultiply(_ a: [UInt32], _ b: [UInt32]) -> [UInt32] {
        var out = [UInt32](repeating: 0, count: a.count + b.count)
        for i in 0..<a.count {
            var carry: UInt64 = 0
            for j in 0..<b.count {
                let current = UInt64(a[i]) * UInt64(b[j]) + UInt64(out[i + j]) + carry
                out[i + j] = UInt32(truncatingIfNeeded: current)
                carry = current >> 32
            }
            out[i + b.count] = UInt32(carry)
        }
        return out
    }

    fileprivate static func shiftRight(_ a: [UInt32], by bits: Int) -> [UInt32] {
        let limbShift = bits / 32
        let bitShift = bits % 32
        guard limbShift < a.count else { return [0] }
        var out = [UInt32](repeating: 0, count: a.count - limbShift)
        for index in 0..<out.count {
            let low = a[index + limbShift] >> UInt32(bitShift)
            var high: UInt32 = 0
            if bitShift != 0, index + limbShift + 1 < a.count {
                high = a[index + limbShift + 1] << UInt32(32 - bitShift)
            }
            out[index] = low | high
        }
        return out
    }

    /// The low `bits` bits of a.
    fileprivate static func lowBits(_ a: [UInt32], _ bits: Int) -> [UInt32] {
        let limbs = (bits + 31) / 32
        var out = pad(Array(a.prefix(limbs)), to: limbs)
        if bits % 32 != 0 {
            out[limbs - 1] &= (UInt32(1) << UInt32(bits % 32)) - 1
        }
        return out
    }

    fileprivate static func bitLength(_ a: [UInt32]) -> Int {
        let trimmed = trim(a)
        let top = trimmed[trimmed.count - 1]
        if top == 0 { return 0 }
        return (trimmed.count - 1) * 32 + (32 - top.leadingZeroBitCount)
    }

    /// Any non-negative integer, brought below p as eight limbs. The bits
    /// above the 255th fold back in times 19, since 2^255 is 19 here, and
    /// what is left is at most a little over p.
    fileprivate static func reduce(_ x: [UInt32]) -> [UInt32] {
        var value = trim(x)
        while bitLength(value) > 256 {
            value = trim(rawAdd(rawMultiply(shiftRight(value, by: 255), [19]), lowBits(value, 255)))
        }
        while compare(value, p) >= 0 {
            value = trim(rawSubtract(value, p))
        }
        return pad(value, to: 8)
    }
}
