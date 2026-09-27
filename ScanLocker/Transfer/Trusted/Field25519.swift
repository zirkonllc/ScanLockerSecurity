import Foundation

nonisolated enum Field25519 {
    static let p: [UInt32] = [0xFFFF_FFED] + Array(repeating: 0xFFFF_FFFF, count: 6) + [0x7FFF_FFFF]

    struct Element: Equatable {
        fileprivate let limbs: [UInt32]

        fileprivate init(reduced limbs: [UInt32]) {
            self.limbs = limbs
        }

        init(_ small: UInt32) {
            limbs = Field25519.pad([small], to: 8)
        }

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

        var sgn0: UInt32 { limbs[0] & 1 }
    }

    static let zero = Element(0)
    static let one = Element(1)

    static func add(_ a: Element, _ b: Element) -> Element {
        Element(reduced: reduce(rawAdd(a.limbs, b.limbs)))
    }

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

    static func invert(_ x: Element) -> Element {
        power(x, pMinus2)
    }

    static func isSquare(_ x: Element) -> Bool {
        let symbol = power(x, legendreExponent)
        return symbol == zero || symbol == one
    }

    static func squareRoot(_ x: Element) -> Element {
        let tv1 = power(x, sqrtExponent)
        let tv2 = multiply(tv1, sqrtMinusOne)
        return square(tv1) == x ? tv1 : tv2
    }

    static let pMinus2 = trim(rawSubtract(p, [2]))
    static let legendreExponent = trim(shiftRight(rawSubtract(p, [1]), by: 1))
    static let sqrtExponent = trim(shiftRight(rawAdd(p, [3]), by: 3))
    static let sqrtMinusOne = power(Element(2), trim(shiftRight(rawSubtract(p, [1]), by: 2)))

    static let J = Element(486662)
    static let K = one
    static let Z = Element(2)
    private static let c1 = multiply(J, invert(K))
    private static let c2 = invert(square(K))
    private static let minusOne = negate(one)
    private static let minusC1 = negate(c1)

    static func elligator2(_ u: Element) -> (s: Element, t: Element) {
        var tv1 = square(u)
        tv1 = multiply(Z, tv1)
        let e1 = tv1 == minusOne
        tv1 = e1 ? zero : tv1
        var x1 = add(tv1, one)
        x1 = invert(x1)
        x1 = multiply(minusC1, x1)
        var gx1 = add(x1, c1)
        gx1 = multiply(gx1, x1)
        gx1 = add(gx1, c2)
        gx1 = multiply(gx1, x1)
        let x2 = subtract(negate(x1), c1)
        let gx2 = multiply(tv1, gx1)
        let e2 = isSquare(gx1)
        let x = e2 ? x1 : x2
        let y2 = e2 ? gx1 : gx2
        var y = squareRoot(y2)
        let e3 = y.sgn0 == 1
        if e2 != e3 { y = negate(y) }
        return (multiply(x, K), multiply(y, K))
    }

    fileprivate static func pad(_ a: [UInt32], to count: Int) -> [UInt32] {
        a.count >= count ? a : a + Array(repeating: 0, count: count - a.count)
    }

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
