(function (global, factory) {
    typeof exports === 'object' && typeof module !== 'undefined' ? factory(exports) :
    typeof define === 'function' && define.amd ? define(['exports'], factory) :
    (global = typeof globalThis !== 'undefined' ? globalThis : global || self, factory(global.NostrEscrow = {}));
})(this, (function (exports) { 'use strict';

    var _nodeResolve_empty = {};

    var nodeCrypto = /*#__PURE__*/Object.freeze({
        __proto__: null,
        default: _nodeResolve_empty
    });

    /*! noble-secp256k1 - MIT License (c) 2019 Paul Miller (paulmillr.com) */
    const _0n = BigInt(0);
    const _1n = BigInt(1);
    const _2n = BigInt(2);
    const _3n = BigInt(3);
    const _8n = BigInt(8);
    const CURVE = Object.freeze({
        a: _0n,
        b: BigInt(7),
        P: BigInt('0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f'),
        n: BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'),
        h: _1n,
        Gx: BigInt('55066263022277343669578718895168534326250603453777594175500187360389116729240'),
        Gy: BigInt('32670510020758816978083085130507043184471273380659243275938904335757337482424'),
        beta: BigInt('0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee'),
    });
    const divNearest = (a, b) => (a + b / _2n) / b;
    const endo = {
        beta: BigInt('0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee'),
        splitScalar(k) {
            const { n } = CURVE;
            const a1 = BigInt('0x3086d221a7d46bcde86c90e49284eb15');
            const b1 = -_1n * BigInt('0xe4437ed6010e88286f547fa90abfe4c3');
            const a2 = BigInt('0x114ca50f7a8e2f3f657c1108d9d44cfd8');
            const b2 = a1;
            const POW_2_128 = BigInt('0x100000000000000000000000000000000');
            const c1 = divNearest(b2 * k, n);
            const c2 = divNearest(-b1 * k, n);
            let k1 = mod(k - c1 * a1 - c2 * a2, n);
            let k2 = mod(-c1 * b1 - c2 * b2, n);
            const k1neg = k1 > POW_2_128;
            const k2neg = k2 > POW_2_128;
            if (k1neg)
                k1 = n - k1;
            if (k2neg)
                k2 = n - k2;
            if (k1 > POW_2_128 || k2 > POW_2_128) {
                throw new Error('splitScalarEndo: Endomorphism failed, k=' + k);
            }
            return { k1neg, k1, k2neg, k2 };
        },
    };
    const fieldLen = 32;
    const groupLen = 32;
    const hashLen = 32;
    const compressedLen = fieldLen + 1;
    const uncompressedLen = 2 * fieldLen + 1;
    function weierstrass(x) {
        const { a, b } = CURVE;
        const x2 = mod(x * x);
        const x3 = mod(x2 * x);
        return mod(x3 + a * x + b);
    }
    const USE_ENDOMORPHISM = CURVE.a === _0n;
    class ShaError extends Error {
        constructor(message) {
            super(message);
        }
    }
    function assertJacPoint(other) {
        if (!(other instanceof JacobianPoint))
            throw new TypeError('JacobianPoint expected');
    }
    class JacobianPoint {
        constructor(x, y, z) {
            this.x = x;
            this.y = y;
            this.z = z;
        }
        static fromAffine(p) {
            if (!(p instanceof Point)) {
                throw new TypeError('JacobianPoint#fromAffine: expected Point');
            }
            if (p.equals(Point.ZERO))
                return JacobianPoint.ZERO;
            return new JacobianPoint(p.x, p.y, _1n);
        }
        static toAffineBatch(points) {
            const toInv = invertBatch(points.map((p) => p.z));
            return points.map((p, i) => p.toAffine(toInv[i]));
        }
        static normalizeZ(points) {
            return JacobianPoint.toAffineBatch(points).map(JacobianPoint.fromAffine);
        }
        equals(other) {
            assertJacPoint(other);
            const { x: X1, y: Y1, z: Z1 } = this;
            const { x: X2, y: Y2, z: Z2 } = other;
            const Z1Z1 = mod(Z1 * Z1);
            const Z2Z2 = mod(Z2 * Z2);
            const U1 = mod(X1 * Z2Z2);
            const U2 = mod(X2 * Z1Z1);
            const S1 = mod(mod(Y1 * Z2) * Z2Z2);
            const S2 = mod(mod(Y2 * Z1) * Z1Z1);
            return U1 === U2 && S1 === S2;
        }
        negate() {
            return new JacobianPoint(this.x, mod(-this.y), this.z);
        }
        double() {
            const { x: X1, y: Y1, z: Z1 } = this;
            const A = mod(X1 * X1);
            const B = mod(Y1 * Y1);
            const C = mod(B * B);
            const x1b = X1 + B;
            const D = mod(_2n * (mod(x1b * x1b) - A - C));
            const E = mod(_3n * A);
            const F = mod(E * E);
            const X3 = mod(F - _2n * D);
            const Y3 = mod(E * (D - X3) - _8n * C);
            const Z3 = mod(_2n * Y1 * Z1);
            return new JacobianPoint(X3, Y3, Z3);
        }
        add(other) {
            assertJacPoint(other);
            const { x: X1, y: Y1, z: Z1 } = this;
            const { x: X2, y: Y2, z: Z2 } = other;
            if (X2 === _0n || Y2 === _0n)
                return this;
            if (X1 === _0n || Y1 === _0n)
                return other;
            const Z1Z1 = mod(Z1 * Z1);
            const Z2Z2 = mod(Z2 * Z2);
            const U1 = mod(X1 * Z2Z2);
            const U2 = mod(X2 * Z1Z1);
            const S1 = mod(mod(Y1 * Z2) * Z2Z2);
            const S2 = mod(mod(Y2 * Z1) * Z1Z1);
            const H = mod(U2 - U1);
            const r = mod(S2 - S1);
            if (H === _0n) {
                if (r === _0n) {
                    return this.double();
                }
                else {
                    return JacobianPoint.ZERO;
                }
            }
            const HH = mod(H * H);
            const HHH = mod(H * HH);
            const V = mod(U1 * HH);
            const X3 = mod(r * r - HHH - _2n * V);
            const Y3 = mod(r * (V - X3) - S1 * HHH);
            const Z3 = mod(Z1 * Z2 * H);
            return new JacobianPoint(X3, Y3, Z3);
        }
        subtract(other) {
            return this.add(other.negate());
        }
        multiplyUnsafe(scalar) {
            const P0 = JacobianPoint.ZERO;
            if (typeof scalar === 'bigint' && scalar === _0n)
                return P0;
            let n = normalizeScalar(scalar);
            if (n === _1n)
                return this;
            if (!USE_ENDOMORPHISM) {
                let p = P0;
                let d = this;
                while (n > _0n) {
                    if (n & _1n)
                        p = p.add(d);
                    d = d.double();
                    n >>= _1n;
                }
                return p;
            }
            let { k1neg, k1, k2neg, k2 } = endo.splitScalar(n);
            let k1p = P0;
            let k2p = P0;
            let d = this;
            while (k1 > _0n || k2 > _0n) {
                if (k1 & _1n)
                    k1p = k1p.add(d);
                if (k2 & _1n)
                    k2p = k2p.add(d);
                d = d.double();
                k1 >>= _1n;
                k2 >>= _1n;
            }
            if (k1neg)
                k1p = k1p.negate();
            if (k2neg)
                k2p = k2p.negate();
            k2p = new JacobianPoint(mod(k2p.x * endo.beta), k2p.y, k2p.z);
            return k1p.add(k2p);
        }
        precomputeWindow(W) {
            const windows = USE_ENDOMORPHISM ? 128 / W + 1 : 256 / W + 1;
            const points = [];
            let p = this;
            let base = p;
            for (let window = 0; window < windows; window++) {
                base = p;
                points.push(base);
                for (let i = 1; i < 2 ** (W - 1); i++) {
                    base = base.add(p);
                    points.push(base);
                }
                p = base.double();
            }
            return points;
        }
        wNAF(n, affinePoint) {
            if (!affinePoint && this.equals(JacobianPoint.BASE))
                affinePoint = Point.BASE;
            const W = (affinePoint && affinePoint._WINDOW_SIZE) || 1;
            if (256 % W) {
                throw new Error('Point#wNAF: Invalid precomputation window, must be power of 2');
            }
            let precomputes = affinePoint && pointPrecomputes.get(affinePoint);
            if (!precomputes) {
                precomputes = this.precomputeWindow(W);
                if (affinePoint && W !== 1) {
                    precomputes = JacobianPoint.normalizeZ(precomputes);
                    pointPrecomputes.set(affinePoint, precomputes);
                }
            }
            let p = JacobianPoint.ZERO;
            let f = JacobianPoint.BASE;
            const windows = 1 + (USE_ENDOMORPHISM ? 128 / W : 256 / W);
            const windowSize = 2 ** (W - 1);
            const mask = BigInt(2 ** W - 1);
            const maxNumber = 2 ** W;
            const shiftBy = BigInt(W);
            for (let window = 0; window < windows; window++) {
                const offset = window * windowSize;
                let wbits = Number(n & mask);
                n >>= shiftBy;
                if (wbits > windowSize) {
                    wbits -= maxNumber;
                    n += _1n;
                }
                const offset1 = offset;
                const offset2 = offset + Math.abs(wbits) - 1;
                const cond1 = window % 2 !== 0;
                const cond2 = wbits < 0;
                if (wbits === 0) {
                    f = f.add(constTimeNegate(cond1, precomputes[offset1]));
                }
                else {
                    p = p.add(constTimeNegate(cond2, precomputes[offset2]));
                }
            }
            return { p, f };
        }
        multiply(scalar, affinePoint) {
            let n = normalizeScalar(scalar);
            let point;
            let fake;
            if (USE_ENDOMORPHISM) {
                const { k1neg, k1, k2neg, k2 } = endo.splitScalar(n);
                let { p: k1p, f: f1p } = this.wNAF(k1, affinePoint);
                let { p: k2p, f: f2p } = this.wNAF(k2, affinePoint);
                k1p = constTimeNegate(k1neg, k1p);
                k2p = constTimeNegate(k2neg, k2p);
                k2p = new JacobianPoint(mod(k2p.x * endo.beta), k2p.y, k2p.z);
                point = k1p.add(k2p);
                fake = f1p.add(f2p);
            }
            else {
                const { p, f } = this.wNAF(n, affinePoint);
                point = p;
                fake = f;
            }
            return JacobianPoint.normalizeZ([point, fake])[0];
        }
        toAffine(invZ) {
            const { x, y, z } = this;
            const is0 = this.equals(JacobianPoint.ZERO);
            if (invZ == null)
                invZ = is0 ? _8n : invert(z);
            const iz1 = invZ;
            const iz2 = mod(iz1 * iz1);
            const iz3 = mod(iz2 * iz1);
            const ax = mod(x * iz2);
            const ay = mod(y * iz3);
            const zz = mod(z * iz1);
            if (is0)
                return Point.ZERO;
            if (zz !== _1n)
                throw new Error('invZ was invalid');
            return new Point(ax, ay);
        }
    }
    JacobianPoint.BASE = new JacobianPoint(CURVE.Gx, CURVE.Gy, _1n);
    JacobianPoint.ZERO = new JacobianPoint(_0n, _1n, _0n);
    function constTimeNegate(condition, item) {
        const neg = item.negate();
        return condition ? neg : item;
    }
    const pointPrecomputes = new WeakMap();
    class Point {
        constructor(x, y) {
            this.x = x;
            this.y = y;
        }
        _setWindowSize(windowSize) {
            this._WINDOW_SIZE = windowSize;
            pointPrecomputes.delete(this);
        }
        hasEvenY() {
            return this.y % _2n === _0n;
        }
        static fromCompressedHex(bytes) {
            const isShort = bytes.length === 32;
            const x = bytesToNumber$1(isShort ? bytes : bytes.subarray(1));
            if (!isValidFieldElement(x))
                throw new Error('Point is not on curve');
            const y2 = weierstrass(x);
            let y = sqrtMod(y2);
            const isYOdd = (y & _1n) === _1n;
            if (isShort) {
                if (isYOdd)
                    y = mod(-y);
            }
            else {
                const isFirstByteOdd = (bytes[0] & 1) === 1;
                if (isFirstByteOdd !== isYOdd)
                    y = mod(-y);
            }
            const point = new Point(x, y);
            point.assertValidity();
            return point;
        }
        static fromUncompressedHex(bytes) {
            const x = bytesToNumber$1(bytes.subarray(1, fieldLen + 1));
            const y = bytesToNumber$1(bytes.subarray(fieldLen + 1, fieldLen * 2 + 1));
            const point = new Point(x, y);
            point.assertValidity();
            return point;
        }
        static fromHex(hex) {
            const bytes = ensureBytes(hex);
            const len = bytes.length;
            const header = bytes[0];
            if (len === fieldLen)
                return this.fromCompressedHex(bytes);
            if (len === compressedLen && (header === 0x02 || header === 0x03)) {
                return this.fromCompressedHex(bytes);
            }
            if (len === uncompressedLen && header === 0x04)
                return this.fromUncompressedHex(bytes);
            throw new Error(`Point.fromHex: received invalid point. Expected 32-${compressedLen} compressed bytes or ${uncompressedLen} uncompressed bytes, not ${len}`);
        }
        static fromPrivateKey(privateKey) {
            return Point.BASE.multiply(normalizePrivateKey(privateKey));
        }
        static fromSignature(msgHash, signature, recovery) {
            const { r, s } = normalizeSignature(signature);
            if (![0, 1, 2, 3].includes(recovery))
                throw new Error('Cannot recover: invalid recovery bit');
            const h = truncateHash(ensureBytes(msgHash));
            const { n } = CURVE;
            const radj = recovery === 2 || recovery === 3 ? r + n : r;
            const rinv = invert(radj, n);
            const u1 = mod(-h * rinv, n);
            const u2 = mod(s * rinv, n);
            const prefix = recovery & 1 ? '03' : '02';
            const R = Point.fromHex(prefix + numTo32bStr(radj));
            const Q = Point.BASE.multiplyAndAddUnsafe(R, u1, u2);
            if (!Q)
                throw new Error('Cannot recover signature: point at infinify');
            Q.assertValidity();
            return Q;
        }
        toRawBytes(isCompressed = false) {
            return hexToBytes$1(this.toHex(isCompressed));
        }
        toHex(isCompressed = false) {
            const x = numTo32bStr(this.x);
            if (isCompressed) {
                const prefix = this.hasEvenY() ? '02' : '03';
                return `${prefix}${x}`;
            }
            else {
                return `04${x}${numTo32bStr(this.y)}`;
            }
        }
        toHexX() {
            return this.toHex(true).slice(2);
        }
        toRawX() {
            return this.toRawBytes(true).slice(1);
        }
        assertValidity() {
            const msg = 'Point is not on elliptic curve';
            const { x, y } = this;
            if (!isValidFieldElement(x) || !isValidFieldElement(y))
                throw new Error(msg);
            const left = mod(y * y);
            const right = weierstrass(x);
            if (mod(left - right) !== _0n)
                throw new Error(msg);
        }
        equals(other) {
            return this.x === other.x && this.y === other.y;
        }
        negate() {
            return new Point(this.x, mod(-this.y));
        }
        double() {
            return JacobianPoint.fromAffine(this).double().toAffine();
        }
        add(other) {
            return JacobianPoint.fromAffine(this).add(JacobianPoint.fromAffine(other)).toAffine();
        }
        subtract(other) {
            return this.add(other.negate());
        }
        multiply(scalar) {
            return JacobianPoint.fromAffine(this).multiply(scalar, this).toAffine();
        }
        multiplyAndAddUnsafe(Q, a, b) {
            const P = JacobianPoint.fromAffine(this);
            const aP = a === _0n || a === _1n || this !== Point.BASE ? P.multiplyUnsafe(a) : P.multiply(a);
            const bQ = JacobianPoint.fromAffine(Q).multiplyUnsafe(b);
            const sum = aP.add(bQ);
            return sum.equals(JacobianPoint.ZERO) ? undefined : sum.toAffine();
        }
    }
    Point.BASE = new Point(CURVE.Gx, CURVE.Gy);
    Point.ZERO = new Point(_0n, _0n);
    function sliceDER(s) {
        return Number.parseInt(s[0], 16) >= 8 ? '00' + s : s;
    }
    function parseDERInt(data) {
        if (data.length < 2 || data[0] !== 0x02) {
            throw new Error(`Invalid signature integer tag: ${bytesToHex$2(data)}`);
        }
        const len = data[1];
        const res = data.subarray(2, len + 2);
        if (!len || res.length !== len) {
            throw new Error(`Invalid signature integer: wrong length`);
        }
        if (res[0] === 0x00 && res[1] <= 0x7f) {
            throw new Error('Invalid signature integer: trailing length');
        }
        return { data: bytesToNumber$1(res), left: data.subarray(len + 2) };
    }
    function parseDERSignature(data) {
        if (data.length < 2 || data[0] != 0x30) {
            throw new Error(`Invalid signature tag: ${bytesToHex$2(data)}`);
        }
        if (data[1] !== data.length - 2) {
            throw new Error('Invalid signature: incorrect length');
        }
        const { data: r, left: sBytes } = parseDERInt(data.subarray(2));
        const { data: s, left: rBytesLeft } = parseDERInt(sBytes);
        if (rBytesLeft.length) {
            throw new Error(`Invalid signature: left bytes after parsing: ${bytesToHex$2(rBytesLeft)}`);
        }
        return { r, s };
    }
    class Signature {
        constructor(r, s) {
            this.r = r;
            this.s = s;
            this.assertValidity();
        }
        static fromCompact(hex) {
            const arr = hex instanceof Uint8Array;
            const name = 'Signature.fromCompact';
            if (typeof hex !== 'string' && !arr)
                throw new TypeError(`${name}: Expected string or Uint8Array`);
            const str = arr ? bytesToHex$2(hex) : hex;
            if (str.length !== 128)
                throw new Error(`${name}: Expected 64-byte hex`);
            return new Signature(hexToNumber(str.slice(0, 64)), hexToNumber(str.slice(64, 128)));
        }
        static fromDER(hex) {
            const arr = hex instanceof Uint8Array;
            if (typeof hex !== 'string' && !arr)
                throw new TypeError(`Signature.fromDER: Expected string or Uint8Array`);
            const { r, s } = parseDERSignature(arr ? hex : hexToBytes$1(hex));
            return new Signature(r, s);
        }
        static fromHex(hex) {
            return this.fromDER(hex);
        }
        assertValidity() {
            const { r, s } = this;
            if (!isWithinCurveOrder(r))
                throw new Error('Invalid Signature: r must be 0 < r < n');
            if (!isWithinCurveOrder(s))
                throw new Error('Invalid Signature: s must be 0 < s < n');
        }
        hasHighS() {
            const HALF = CURVE.n >> _1n;
            return this.s > HALF;
        }
        normalizeS() {
            return this.hasHighS() ? new Signature(this.r, mod(-this.s, CURVE.n)) : this;
        }
        toDERRawBytes() {
            return hexToBytes$1(this.toDERHex());
        }
        toDERHex() {
            const sHex = sliceDER(numberToHexUnpadded(this.s));
            const rHex = sliceDER(numberToHexUnpadded(this.r));
            const sHexL = sHex.length / 2;
            const rHexL = rHex.length / 2;
            const sLen = numberToHexUnpadded(sHexL);
            const rLen = numberToHexUnpadded(rHexL);
            const length = numberToHexUnpadded(rHexL + sHexL + 4);
            return `30${length}02${rLen}${rHex}02${sLen}${sHex}`;
        }
        toRawBytes() {
            return this.toDERRawBytes();
        }
        toHex() {
            return this.toDERHex();
        }
        toCompactRawBytes() {
            return hexToBytes$1(this.toCompactHex());
        }
        toCompactHex() {
            return numTo32bStr(this.r) + numTo32bStr(this.s);
        }
    }
    function concatBytes$1(...arrays) {
        if (!arrays.every((b) => b instanceof Uint8Array))
            throw new Error('Uint8Array list expected');
        if (arrays.length === 1)
            return arrays[0];
        const length = arrays.reduce((a, arr) => a + arr.length, 0);
        const result = new Uint8Array(length);
        for (let i = 0, pad = 0; i < arrays.length; i++) {
            const arr = arrays[i];
            result.set(arr, pad);
            pad += arr.length;
        }
        return result;
    }
    const hexes$2 = Array.from({ length: 256 }, (v, i) => i.toString(16).padStart(2, '0'));
    function bytesToHex$2(uint8a) {
        if (!(uint8a instanceof Uint8Array))
            throw new Error('Expected Uint8Array');
        let hex = '';
        for (let i = 0; i < uint8a.length; i++) {
            hex += hexes$2[uint8a[i]];
        }
        return hex;
    }
    const POW_2_256 = BigInt('0x10000000000000000000000000000000000000000000000000000000000000000');
    function numTo32bStr(num) {
        if (typeof num !== 'bigint')
            throw new Error('Expected bigint');
        if (!(_0n <= num && num < POW_2_256))
            throw new Error('Expected number 0 <= n < 2^256');
        return num.toString(16).padStart(64, '0');
    }
    function numTo32b(num) {
        const b = hexToBytes$1(numTo32bStr(num));
        if (b.length !== 32)
            throw new Error('Error: expected 32 bytes');
        return b;
    }
    function numberToHexUnpadded(num) {
        const hex = num.toString(16);
        return hex.length & 1 ? `0${hex}` : hex;
    }
    function hexToNumber(hex) {
        if (typeof hex !== 'string') {
            throw new TypeError('hexToNumber: expected string, got ' + typeof hex);
        }
        return BigInt(`0x${hex}`);
    }
    function hexToBytes$1(hex) {
        if (typeof hex !== 'string') {
            throw new TypeError('hexToBytes: expected string, got ' + typeof hex);
        }
        if (hex.length % 2)
            throw new Error('hexToBytes: received invalid unpadded hex' + hex.length);
        const array = new Uint8Array(hex.length / 2);
        for (let i = 0; i < array.length; i++) {
            const j = i * 2;
            const hexByte = hex.slice(j, j + 2);
            const byte = Number.parseInt(hexByte, 16);
            if (Number.isNaN(byte) || byte < 0)
                throw new Error('Invalid byte sequence');
            array[i] = byte;
        }
        return array;
    }
    function bytesToNumber$1(bytes) {
        return hexToNumber(bytesToHex$2(bytes));
    }
    function ensureBytes(hex) {
        return hex instanceof Uint8Array ? Uint8Array.from(hex) : hexToBytes$1(hex);
    }
    function normalizeScalar(num) {
        if (typeof num === 'number' && Number.isSafeInteger(num) && num > 0)
            return BigInt(num);
        if (typeof num === 'bigint' && isWithinCurveOrder(num))
            return num;
        throw new TypeError('Expected valid private scalar: 0 < scalar < curve.n');
    }
    function mod(a, b = CURVE.P) {
        const result = a % b;
        return result >= _0n ? result : b + result;
    }
    function pow2(x, power) {
        const { P } = CURVE;
        let res = x;
        while (power-- > _0n) {
            res *= res;
            res %= P;
        }
        return res;
    }
    function sqrtMod(x) {
        const { P } = CURVE;
        const _6n = BigInt(6);
        const _11n = BigInt(11);
        const _22n = BigInt(22);
        const _23n = BigInt(23);
        const _44n = BigInt(44);
        const _88n = BigInt(88);
        const b2 = (x * x * x) % P;
        const b3 = (b2 * b2 * x) % P;
        const b6 = (pow2(b3, _3n) * b3) % P;
        const b9 = (pow2(b6, _3n) * b3) % P;
        const b11 = (pow2(b9, _2n) * b2) % P;
        const b22 = (pow2(b11, _11n) * b11) % P;
        const b44 = (pow2(b22, _22n) * b22) % P;
        const b88 = (pow2(b44, _44n) * b44) % P;
        const b176 = (pow2(b88, _88n) * b88) % P;
        const b220 = (pow2(b176, _44n) * b44) % P;
        const b223 = (pow2(b220, _3n) * b3) % P;
        const t1 = (pow2(b223, _23n) * b22) % P;
        const t2 = (pow2(t1, _6n) * b2) % P;
        const rt = pow2(t2, _2n);
        const xc = (rt * rt) % P;
        if (xc !== x)
            throw new Error('Cannot find square root');
        return rt;
    }
    function invert(number, modulo = CURVE.P) {
        if (number === _0n || modulo <= _0n) {
            throw new Error(`invert: expected positive integers, got n=${number} mod=${modulo}`);
        }
        let a = mod(number, modulo);
        let b = modulo;
        let x = _0n, u = _1n;
        while (a !== _0n) {
            const q = b / a;
            const r = b % a;
            const m = x - u * q;
            b = a, a = r, x = u, u = m;
        }
        const gcd = b;
        if (gcd !== _1n)
            throw new Error('invert: does not exist');
        return mod(x, modulo);
    }
    function invertBatch(nums, p = CURVE.P) {
        const scratch = new Array(nums.length);
        const lastMultiplied = nums.reduce((acc, num, i) => {
            if (num === _0n)
                return acc;
            scratch[i] = acc;
            return mod(acc * num, p);
        }, _1n);
        const inverted = invert(lastMultiplied, p);
        nums.reduceRight((acc, num, i) => {
            if (num === _0n)
                return acc;
            scratch[i] = mod(acc * scratch[i], p);
            return mod(acc * num, p);
        }, inverted);
        return scratch;
    }
    function bits2int_2(bytes) {
        const delta = bytes.length * 8 - groupLen * 8;
        const num = bytesToNumber$1(bytes);
        return delta > 0 ? num >> BigInt(delta) : num;
    }
    function truncateHash(hash, truncateOnly = false) {
        const h = bits2int_2(hash);
        if (truncateOnly)
            return h;
        const { n } = CURVE;
        return h >= n ? h - n : h;
    }
    let _sha256Sync;
    let _hmacSha256Sync;
    class HmacDrbg {
        constructor(hashLen, qByteLen) {
            this.hashLen = hashLen;
            this.qByteLen = qByteLen;
            if (typeof hashLen !== 'number' || hashLen < 2)
                throw new Error('hashLen must be a number');
            if (typeof qByteLen !== 'number' || qByteLen < 2)
                throw new Error('qByteLen must be a number');
            this.v = new Uint8Array(hashLen).fill(1);
            this.k = new Uint8Array(hashLen).fill(0);
            this.counter = 0;
        }
        hmac(...values) {
            return utils$1.hmacSha256(this.k, ...values);
        }
        hmacSync(...values) {
            return _hmacSha256Sync(this.k, ...values);
        }
        checkSync() {
            if (typeof _hmacSha256Sync !== 'function')
                throw new ShaError('hmacSha256Sync needs to be set');
        }
        incr() {
            if (this.counter >= 1000)
                throw new Error('Tried 1,000 k values for sign(), all were invalid');
            this.counter += 1;
        }
        async reseed(seed = new Uint8Array()) {
            this.k = await this.hmac(this.v, Uint8Array.from([0x00]), seed);
            this.v = await this.hmac(this.v);
            if (seed.length === 0)
                return;
            this.k = await this.hmac(this.v, Uint8Array.from([0x01]), seed);
            this.v = await this.hmac(this.v);
        }
        reseedSync(seed = new Uint8Array()) {
            this.checkSync();
            this.k = this.hmacSync(this.v, Uint8Array.from([0x00]), seed);
            this.v = this.hmacSync(this.v);
            if (seed.length === 0)
                return;
            this.k = this.hmacSync(this.v, Uint8Array.from([0x01]), seed);
            this.v = this.hmacSync(this.v);
        }
        async generate() {
            this.incr();
            let len = 0;
            const out = [];
            while (len < this.qByteLen) {
                this.v = await this.hmac(this.v);
                const sl = this.v.slice();
                out.push(sl);
                len += this.v.length;
            }
            return concatBytes$1(...out);
        }
        generateSync() {
            this.checkSync();
            this.incr();
            let len = 0;
            const out = [];
            while (len < this.qByteLen) {
                this.v = this.hmacSync(this.v);
                const sl = this.v.slice();
                out.push(sl);
                len += this.v.length;
            }
            return concatBytes$1(...out);
        }
    }
    function isWithinCurveOrder(num) {
        return _0n < num && num < CURVE.n;
    }
    function isValidFieldElement(num) {
        return _0n < num && num < CURVE.P;
    }
    function kmdToSig(kBytes, m, d, lowS = true) {
        const { n } = CURVE;
        const k = truncateHash(kBytes, true);
        if (!isWithinCurveOrder(k))
            return;
        const kinv = invert(k, n);
        const q = Point.BASE.multiply(k);
        const r = mod(q.x, n);
        if (r === _0n)
            return;
        const s = mod(kinv * mod(m + d * r, n), n);
        if (s === _0n)
            return;
        let sig = new Signature(r, s);
        let recovery = (q.x === sig.r ? 0 : 2) | Number(q.y & _1n);
        if (lowS && sig.hasHighS()) {
            sig = sig.normalizeS();
            recovery ^= 1;
        }
        return { sig, recovery };
    }
    function normalizePrivateKey(key) {
        let num;
        if (typeof key === 'bigint') {
            num = key;
        }
        else if (typeof key === 'number' && Number.isSafeInteger(key) && key > 0) {
            num = BigInt(key);
        }
        else if (typeof key === 'string') {
            if (key.length !== 2 * groupLen)
                throw new Error('Expected 32 bytes of private key');
            num = hexToNumber(key);
        }
        else if (key instanceof Uint8Array) {
            if (key.length !== groupLen)
                throw new Error('Expected 32 bytes of private key');
            num = bytesToNumber$1(key);
        }
        else {
            throw new TypeError('Expected valid private key');
        }
        if (!isWithinCurveOrder(num))
            throw new Error('Expected private key: 0 < key < n');
        return num;
    }
    function normalizePublicKey(publicKey) {
        if (publicKey instanceof Point) {
            publicKey.assertValidity();
            return publicKey;
        }
        else {
            return Point.fromHex(publicKey);
        }
    }
    function normalizeSignature(signature) {
        if (signature instanceof Signature) {
            signature.assertValidity();
            return signature;
        }
        try {
            return Signature.fromDER(signature);
        }
        catch (error) {
            return Signature.fromCompact(signature);
        }
    }
    function getPublicKey$1(privateKey, isCompressed = false) {
        return Point.fromPrivateKey(privateKey).toRawBytes(isCompressed);
    }
    function isProbPub(item) {
        const arr = item instanceof Uint8Array;
        const str = typeof item === 'string';
        const len = (arr || str) && item.length;
        if (arr)
            return len === compressedLen || len === uncompressedLen;
        if (str)
            return len === compressedLen * 2 || len === uncompressedLen * 2;
        if (item instanceof Point)
            return true;
        return false;
    }
    function getSharedSecret(privateA, publicB, isCompressed = false) {
        if (isProbPub(privateA))
            throw new TypeError('getSharedSecret: first arg must be private key');
        if (!isProbPub(publicB))
            throw new TypeError('getSharedSecret: second arg must be public key');
        const b = normalizePublicKey(publicB);
        b.assertValidity();
        return b.multiply(normalizePrivateKey(privateA)).toRawBytes(isCompressed);
    }
    function bits2int(bytes) {
        const slice = bytes.length > fieldLen ? bytes.slice(0, fieldLen) : bytes;
        return bytesToNumber$1(slice);
    }
    function bits2octets(bytes) {
        const z1 = bits2int(bytes);
        const z2 = mod(z1, CURVE.n);
        return int2octets(z2 < _0n ? z1 : z2);
    }
    function int2octets(num) {
        return numTo32b(num);
    }
    function initSigArgs(msgHash, privateKey, extraEntropy) {
        if (msgHash == null)
            throw new Error(`sign: expected valid message hash, not "${msgHash}"`);
        const h1 = ensureBytes(msgHash);
        const d = normalizePrivateKey(privateKey);
        const seedArgs = [int2octets(d), bits2octets(h1)];
        if (extraEntropy != null) {
            if (extraEntropy === true)
                extraEntropy = utils$1.randomBytes(fieldLen);
            const e = ensureBytes(extraEntropy);
            if (e.length !== fieldLen)
                throw new Error(`sign: Expected ${fieldLen} bytes of extra data`);
            seedArgs.push(e);
        }
        const seed = concatBytes$1(...seedArgs);
        const m = bits2int(h1);
        return { seed, m, d };
    }
    function finalizeSig(recSig, opts) {
        const { sig, recovery } = recSig;
        const { der, recovered } = Object.assign({ canonical: true, der: true }, opts);
        const hashed = der ? sig.toDERRawBytes() : sig.toCompactRawBytes();
        return recovered ? [hashed, recovery] : hashed;
    }
    function signSync(msgHash, privKey, opts = {}) {
        const { seed, m, d } = initSigArgs(msgHash, privKey, opts.extraEntropy);
        const drbg = new HmacDrbg(hashLen, groupLen);
        drbg.reseedSync(seed);
        let sig;
        while (!(sig = kmdToSig(drbg.generateSync(), m, d, opts.canonical)))
            drbg.reseedSync();
        return finalizeSig(sig, opts);
    }
    const vopts = { strict: true };
    function verify(signature, msgHash, publicKey, opts = vopts) {
        let sig;
        try {
            sig = normalizeSignature(signature);
            msgHash = ensureBytes(msgHash);
        }
        catch (error) {
            return false;
        }
        const { r, s } = sig;
        if (opts.strict && sig.hasHighS())
            return false;
        const h = truncateHash(msgHash);
        let P;
        try {
            P = normalizePublicKey(publicKey);
        }
        catch (error) {
            return false;
        }
        const { n } = CURVE;
        const sinv = invert(s, n);
        const u1 = mod(h * sinv, n);
        const u2 = mod(r * sinv, n);
        const R = Point.BASE.multiplyAndAddUnsafe(P, u1, u2);
        if (!R)
            return false;
        const v = mod(R.x, n);
        return v === r;
    }
    function schnorrChallengeFinalize(ch) {
        return mod(bytesToNumber$1(ch), CURVE.n);
    }
    class SchnorrSignature {
        constructor(r, s) {
            this.r = r;
            this.s = s;
            this.assertValidity();
        }
        static fromHex(hex) {
            const bytes = ensureBytes(hex);
            if (bytes.length !== 64)
                throw new TypeError(`SchnorrSignature.fromHex: expected 64 bytes, not ${bytes.length}`);
            const r = bytesToNumber$1(bytes.subarray(0, 32));
            const s = bytesToNumber$1(bytes.subarray(32, 64));
            return new SchnorrSignature(r, s);
        }
        assertValidity() {
            const { r, s } = this;
            if (!isValidFieldElement(r) || !isWithinCurveOrder(s))
                throw new Error('Invalid signature');
        }
        toHex() {
            return numTo32bStr(this.r) + numTo32bStr(this.s);
        }
        toRawBytes() {
            return hexToBytes$1(this.toHex());
        }
    }
    function schnorrGetPublicKey(privateKey) {
        return Point.fromPrivateKey(privateKey).toRawX();
    }
    class InternalSchnorrSignature {
        constructor(message, privateKey, auxRand = utils$1.randomBytes()) {
            if (message == null)
                throw new TypeError(`sign: Expected valid message, not "${message}"`);
            this.m = ensureBytes(message);
            const { x, scalar } = this.getScalar(normalizePrivateKey(privateKey));
            this.px = x;
            this.d = scalar;
            this.rand = ensureBytes(auxRand);
            if (this.rand.length !== 32)
                throw new TypeError('sign: Expected 32 bytes of aux randomness');
        }
        getScalar(priv) {
            const point = Point.fromPrivateKey(priv);
            const scalar = point.hasEvenY() ? priv : CURVE.n - priv;
            return { point, scalar, x: point.toRawX() };
        }
        initNonce(d, t0h) {
            return numTo32b(d ^ bytesToNumber$1(t0h));
        }
        finalizeNonce(k0h) {
            const k0 = mod(bytesToNumber$1(k0h), CURVE.n);
            if (k0 === _0n)
                throw new Error('sign: Creation of signature failed. k is zero');
            const { point: R, x: rx, scalar: k } = this.getScalar(k0);
            return { R, rx, k };
        }
        finalizeSig(R, k, e, d) {
            return new SchnorrSignature(R.x, mod(k + e * d, CURVE.n)).toRawBytes();
        }
        error() {
            throw new Error('sign: Invalid signature produced');
        }
        async calc() {
            const { m, d, px, rand } = this;
            const tag = utils$1.taggedHash;
            const t = this.initNonce(d, await tag(TAGS.aux, rand));
            const { R, rx, k } = this.finalizeNonce(await tag(TAGS.nonce, t, px, m));
            const e = schnorrChallengeFinalize(await tag(TAGS.challenge, rx, px, m));
            const sig = this.finalizeSig(R, k, e, d);
            if (!(await schnorrVerify(sig, m, px)))
                this.error();
            return sig;
        }
        calcSync() {
            const { m, d, px, rand } = this;
            const tag = utils$1.taggedHashSync;
            const t = this.initNonce(d, tag(TAGS.aux, rand));
            const { R, rx, k } = this.finalizeNonce(tag(TAGS.nonce, t, px, m));
            const e = schnorrChallengeFinalize(tag(TAGS.challenge, rx, px, m));
            const sig = this.finalizeSig(R, k, e, d);
            if (!schnorrVerifySync(sig, m, px))
                this.error();
            return sig;
        }
    }
    async function schnorrSign(msg, privKey, auxRand) {
        return new InternalSchnorrSignature(msg, privKey, auxRand).calc();
    }
    function schnorrSignSync(msg, privKey, auxRand) {
        return new InternalSchnorrSignature(msg, privKey, auxRand).calcSync();
    }
    function initSchnorrVerify(signature, message, publicKey) {
        const raw = signature instanceof SchnorrSignature;
        const sig = raw ? signature : SchnorrSignature.fromHex(signature);
        if (raw)
            sig.assertValidity();
        return {
            ...sig,
            m: ensureBytes(message),
            P: normalizePublicKey(publicKey),
        };
    }
    function finalizeSchnorrVerify(r, P, s, e) {
        const R = Point.BASE.multiplyAndAddUnsafe(P, normalizePrivateKey(s), mod(-e, CURVE.n));
        if (!R || !R.hasEvenY() || R.x !== r)
            return false;
        return true;
    }
    async function schnorrVerify(signature, message, publicKey) {
        try {
            const { r, s, m, P } = initSchnorrVerify(signature, message, publicKey);
            const e = schnorrChallengeFinalize(await utils$1.taggedHash(TAGS.challenge, numTo32b(r), P.toRawX(), m));
            return finalizeSchnorrVerify(r, P, s, e);
        }
        catch (error) {
            return false;
        }
    }
    function schnorrVerifySync(signature, message, publicKey) {
        try {
            const { r, s, m, P } = initSchnorrVerify(signature, message, publicKey);
            const e = schnorrChallengeFinalize(utils$1.taggedHashSync(TAGS.challenge, numTo32b(r), P.toRawX(), m));
            return finalizeSchnorrVerify(r, P, s, e);
        }
        catch (error) {
            if (error instanceof ShaError)
                throw error;
            return false;
        }
    }
    const schnorr = {
        Signature: SchnorrSignature,
        getPublicKey: schnorrGetPublicKey,
        sign: schnorrSign,
        verify: schnorrVerify,
        signSync: schnorrSignSync,
        verifySync: schnorrVerifySync,
    };
    Point.BASE._setWindowSize(8);
    const crypto$2 = {
        node: nodeCrypto,
        web: typeof self === 'object' && 'crypto' in self ? self.crypto : undefined,
    };
    const TAGS = {
        challenge: 'BIP0340/challenge',
        aux: 'BIP0340/aux',
        nonce: 'BIP0340/nonce',
    };
    const TAGGED_HASH_PREFIXES = {};
    const utils$1 = {
        bytesToHex: bytesToHex$2,
        hexToBytes: hexToBytes$1,
        concatBytes: concatBytes$1,
        mod,
        invert,
        isValidPrivateKey(privateKey) {
            try {
                normalizePrivateKey(privateKey);
                return true;
            }
            catch (error) {
                return false;
            }
        },
        _bigintTo32Bytes: numTo32b,
        _normalizePrivateKey: normalizePrivateKey,
        hashToPrivateKey: (hash) => {
            hash = ensureBytes(hash);
            const minLen = groupLen + 8;
            if (hash.length < minLen || hash.length > 1024) {
                throw new Error(`Expected valid bytes of private key as per FIPS 186`);
            }
            const num = mod(bytesToNumber$1(hash), CURVE.n - _1n) + _1n;
            return numTo32b(num);
        },
        randomBytes: (bytesLength = 32) => {
            if (crypto$2.web) {
                return crypto$2.web.getRandomValues(new Uint8Array(bytesLength));
            }
            else if (crypto$2.node) {
                const { randomBytes } = crypto$2.node;
                return Uint8Array.from(randomBytes(bytesLength));
            }
            else {
                throw new Error("The environment doesn't have randomBytes function");
            }
        },
        randomPrivateKey: () => utils$1.hashToPrivateKey(utils$1.randomBytes(groupLen + 8)),
        precompute(windowSize = 8, point = Point.BASE) {
            const cached = point === Point.BASE ? point : new Point(point.x, point.y);
            cached._setWindowSize(windowSize);
            cached.multiply(_3n);
            return cached;
        },
        sha256: async (...messages) => {
            if (crypto$2.web) {
                const buffer = await crypto$2.web.subtle.digest('SHA-256', concatBytes$1(...messages));
                return new Uint8Array(buffer);
            }
            else if (crypto$2.node) {
                const { createHash } = crypto$2.node;
                const hash = createHash('sha256');
                messages.forEach((m) => hash.update(m));
                return Uint8Array.from(hash.digest());
            }
            else {
                throw new Error("The environment doesn't have sha256 function");
            }
        },
        hmacSha256: async (key, ...messages) => {
            if (crypto$2.web) {
                const ckey = await crypto$2.web.subtle.importKey('raw', key, { name: 'HMAC', hash: { name: 'SHA-256' } }, false, ['sign']);
                const message = concatBytes$1(...messages);
                const buffer = await crypto$2.web.subtle.sign('HMAC', ckey, message);
                return new Uint8Array(buffer);
            }
            else if (crypto$2.node) {
                const { createHmac } = crypto$2.node;
                const hash = createHmac('sha256', key);
                messages.forEach((m) => hash.update(m));
                return Uint8Array.from(hash.digest());
            }
            else {
                throw new Error("The environment doesn't have hmac-sha256 function");
            }
        },
        sha256Sync: undefined,
        hmacSha256Sync: undefined,
        taggedHash: async (tag, ...messages) => {
            let tagP = TAGGED_HASH_PREFIXES[tag];
            if (tagP === undefined) {
                const tagH = await utils$1.sha256(Uint8Array.from(tag, (c) => c.charCodeAt(0)));
                tagP = concatBytes$1(tagH, tagH);
                TAGGED_HASH_PREFIXES[tag] = tagP;
            }
            return utils$1.sha256(tagP, ...messages);
        },
        taggedHashSync: (tag, ...messages) => {
            if (typeof _sha256Sync !== 'function')
                throw new ShaError('sha256Sync is undefined, you need to set it');
            let tagP = TAGGED_HASH_PREFIXES[tag];
            if (tagP === undefined) {
                const tagH = _sha256Sync(Uint8Array.from(tag, (c) => c.charCodeAt(0)));
                tagP = concatBytes$1(tagH, tagH);
                TAGGED_HASH_PREFIXES[tag] = tagP;
            }
            return _sha256Sync(tagP, ...messages);
        },
        _JacobianPoint: JacobianPoint,
    };
    Object.defineProperties(utils$1, {
        sha256Sync: {
            configurable: false,
            get() {
                return _sha256Sync;
            },
            set(val) {
                if (!_sha256Sync)
                    _sha256Sync = val;
            },
        },
        hmacSha256Sync: {
            configurable: false,
            get() {
                return _hmacSha256Sync;
            },
            set(val) {
                if (!_hmacSha256Sync)
                    _hmacSha256Sync = val;
            },
        },
    });

    function number$3(n) {
        if (!Number.isSafeInteger(n) || n < 0)
            throw new Error(`Wrong positive integer: ${n}`);
    }
    function bool$3(b) {
        if (typeof b !== 'boolean')
            throw new Error(`Expected boolean, not ${b}`);
    }
    function bytes$3(b, ...lengths) {
        if (!(b instanceof Uint8Array))
            throw new TypeError('Expected Uint8Array');
        if (lengths.length > 0 && !lengths.includes(b.length))
            throw new TypeError(`Expected Uint8Array of length ${lengths}, not of length=${b.length}`);
    }
    function hash$3(hash) {
        if (typeof hash !== 'function' || typeof hash.create !== 'function')
            throw new Error('Hash should be wrapped by utils.wrapConstructor');
        number$3(hash.outputLen);
        number$3(hash.blockLen);
    }
    function exists$3(instance, checkFinished = true) {
        if (instance.destroyed)
            throw new Error('Hash instance has been destroyed');
        if (checkFinished && instance.finished)
            throw new Error('Hash#digest() has already been called');
    }
    function output$3(out, instance) {
        bytes$3(out);
        const min = instance.outputLen;
        if (out.length < min) {
            throw new Error(`digestInto() expects output buffer of length at least ${min}`);
        }
    }
    const assert$4 = {
        number: number$3,
        bool: bool$3,
        bytes: bytes$3,
        hash: hash$3,
        exists: exists$3,
        output: output$3,
    };

    const crypto$1 = {
        node: undefined,
        web: typeof self === 'object' && 'crypto' in self ? self.crypto : undefined,
    };

    /*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) */
    // The import here is via the package name. This is to ensure
    // that exports mapping/resolution does fall into place.
    // Cast array to view
    const createView$2 = (arr) => new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
    // The rotate right (circular right shift) operation for uint32
    const rotr$2 = (word, shift) => (word << (32 - shift)) | (word >>> shift);
    const isLE$2 = new Uint8Array(new Uint32Array([0x11223344]).buffer)[0] === 0x44;
    // There is almost no big endian hardware, but js typed arrays uses platform specific endianness.
    // So, just to be sure not to corrupt anything.
    if (!isLE$2)
        throw new Error('Non little-endian hardware is not supported');
    Array.from({ length: 256 }, (v, i) => i.toString(16).padStart(2, '0'));
    function utf8ToBytes$2(str) {
        if (typeof str !== 'string') {
            throw new TypeError(`utf8ToBytes expected string, got ${typeof str}`);
        }
        return new TextEncoder().encode(str);
    }
    function toBytes$2(data) {
        if (typeof data === 'string')
            data = utf8ToBytes$2(data);
        if (!(data instanceof Uint8Array))
            throw new TypeError(`Expected input type is Uint8Array (got ${typeof data})`);
        return data;
    }
    // For runtime check if class implements interface
    let Hash$2 = class Hash {
        // Safe version that clones internal state
        clone() {
            return this._cloneInto();
        }
    };
    function wrapConstructor$2(hashConstructor) {
        const hashC = (message) => hashConstructor().update(toBytes$2(message)).digest();
        const tmp = hashConstructor();
        hashC.outputLen = tmp.outputLen;
        hashC.blockLen = tmp.blockLen;
        hashC.create = () => hashConstructor();
        return hashC;
    }
    /**
     * Secure PRNG
     */
    function randomBytes(bytesLength = 32) {
        if (crypto$1.web) {
            return crypto$1.web.getRandomValues(new Uint8Array(bytesLength));
        }
        else {
            throw new Error("The environment doesn't have randomBytes function");
        }
    }

    // Polyfill for Safari 14
    function setBigUint64$3(view, byteOffset, value, isLE) {
        if (typeof view.setBigUint64 === 'function')
            return view.setBigUint64(byteOffset, value, isLE);
        const _32n = BigInt(32);
        const _u32_max = BigInt(0xffffffff);
        const wh = Number((value >> _32n) & _u32_max);
        const wl = Number(value & _u32_max);
        const h = isLE ? 4 : 0;
        const l = isLE ? 0 : 4;
        view.setUint32(byteOffset + h, wh, isLE);
        view.setUint32(byteOffset + l, wl, isLE);
    }
    // Base SHA2 class (RFC 6234)
    let SHA2$3 = class SHA2 extends Hash$2 {
        constructor(blockLen, outputLen, padOffset, isLE) {
            super();
            this.blockLen = blockLen;
            this.outputLen = outputLen;
            this.padOffset = padOffset;
            this.isLE = isLE;
            this.finished = false;
            this.length = 0;
            this.pos = 0;
            this.destroyed = false;
            this.buffer = new Uint8Array(blockLen);
            this.view = createView$2(this.buffer);
        }
        update(data) {
            assert$4.exists(this);
            const { view, buffer, blockLen } = this;
            data = toBytes$2(data);
            const len = data.length;
            for (let pos = 0; pos < len;) {
                const take = Math.min(blockLen - this.pos, len - pos);
                // Fast path: we have at least one block in input, cast it to view and process
                if (take === blockLen) {
                    const dataView = createView$2(data);
                    for (; blockLen <= len - pos; pos += blockLen)
                        this.process(dataView, pos);
                    continue;
                }
                buffer.set(data.subarray(pos, pos + take), this.pos);
                this.pos += take;
                pos += take;
                if (this.pos === blockLen) {
                    this.process(view, 0);
                    this.pos = 0;
                }
            }
            this.length += data.length;
            this.roundClean();
            return this;
        }
        digestInto(out) {
            assert$4.exists(this);
            assert$4.output(out, this);
            this.finished = true;
            // Padding
            // We can avoid allocation of buffer for padding completely if it
            // was previously not allocated here. But it won't change performance.
            const { buffer, view, blockLen, isLE } = this;
            let { pos } = this;
            // append the bit '1' to the message
            buffer[pos++] = 0b10000000;
            this.buffer.subarray(pos).fill(0);
            // we have less than padOffset left in buffer, so we cannot put length in current block, need process it and pad again
            if (this.padOffset > blockLen - pos) {
                this.process(view, 0);
                pos = 0;
            }
            // Pad until full block byte with zeros
            for (let i = pos; i < blockLen; i++)
                buffer[i] = 0;
            // Note: sha512 requires length to be 128bit integer, but length in JS will overflow before that
            // You need to write around 2 exabytes (u64_max / 8 / (1024**6)) for this to happen.
            // So we just write lowest 64 bits of that value.
            setBigUint64$3(view, blockLen - 8, BigInt(this.length * 8), isLE);
            this.process(view, 0);
            const oview = createView$2(out);
            const len = this.outputLen;
            // NOTE: we do division by 4 later, which should be fused in single op with modulo by JIT
            if (len % 4)
                throw new Error('_sha2: outputLen should be aligned to 32bit');
            const outLen = len / 4;
            const state = this.get();
            if (outLen > state.length)
                throw new Error('_sha2: outputLen bigger than state');
            for (let i = 0; i < outLen; i++)
                oview.setUint32(4 * i, state[i], isLE);
        }
        digest() {
            const { buffer, outputLen } = this;
            this.digestInto(buffer);
            const res = buffer.slice(0, outputLen);
            this.destroy();
            return res;
        }
        _cloneInto(to) {
            to || (to = new this.constructor());
            to.set(...this.get());
            const { blockLen, buffer, length, finished, destroyed, pos } = this;
            to.length = length;
            to.pos = pos;
            to.finished = finished;
            to.destroyed = destroyed;
            if (length % blockLen)
                to.buffer.set(buffer);
            return to;
        }
    };

    // Choice: a ? b : c
    const Chi$3 = (a, b, c) => (a & b) ^ (~a & c);
    // Majority function, true if any two inpust is true
    const Maj$3 = (a, b, c) => (a & b) ^ (a & c) ^ (b & c);
    // Round constants:
    // first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311)
    // prettier-ignore
    const SHA256_K$3 = new Uint32Array([
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]);
    // Initial state (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
    // prettier-ignore
    const IV$3 = new Uint32Array([
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]);
    // Temporary buffer, not used to store anything between runs
    // Named this way because it matches specification.
    const SHA256_W$3 = new Uint32Array(64);
    let SHA256$3 = class SHA256 extends SHA2$3 {
        constructor() {
            super(64, 32, 8, false);
            // We cannot use array here since array allows indexing by variable
            // which means optimizer/compiler cannot use registers.
            this.A = IV$3[0] | 0;
            this.B = IV$3[1] | 0;
            this.C = IV$3[2] | 0;
            this.D = IV$3[3] | 0;
            this.E = IV$3[4] | 0;
            this.F = IV$3[5] | 0;
            this.G = IV$3[6] | 0;
            this.H = IV$3[7] | 0;
        }
        get() {
            const { A, B, C, D, E, F, G, H } = this;
            return [A, B, C, D, E, F, G, H];
        }
        // prettier-ignore
        set(A, B, C, D, E, F, G, H) {
            this.A = A | 0;
            this.B = B | 0;
            this.C = C | 0;
            this.D = D | 0;
            this.E = E | 0;
            this.F = F | 0;
            this.G = G | 0;
            this.H = H | 0;
        }
        process(view, offset) {
            // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array
            for (let i = 0; i < 16; i++, offset += 4)
                SHA256_W$3[i] = view.getUint32(offset, false);
            for (let i = 16; i < 64; i++) {
                const W15 = SHA256_W$3[i - 15];
                const W2 = SHA256_W$3[i - 2];
                const s0 = rotr$2(W15, 7) ^ rotr$2(W15, 18) ^ (W15 >>> 3);
                const s1 = rotr$2(W2, 17) ^ rotr$2(W2, 19) ^ (W2 >>> 10);
                SHA256_W$3[i] = (s1 + SHA256_W$3[i - 7] + s0 + SHA256_W$3[i - 16]) | 0;
            }
            // Compression function main loop, 64 rounds
            let { A, B, C, D, E, F, G, H } = this;
            for (let i = 0; i < 64; i++) {
                const sigma1 = rotr$2(E, 6) ^ rotr$2(E, 11) ^ rotr$2(E, 25);
                const T1 = (H + sigma1 + Chi$3(E, F, G) + SHA256_K$3[i] + SHA256_W$3[i]) | 0;
                const sigma0 = rotr$2(A, 2) ^ rotr$2(A, 13) ^ rotr$2(A, 22);
                const T2 = (sigma0 + Maj$3(A, B, C)) | 0;
                H = G;
                G = F;
                F = E;
                E = (D + T1) | 0;
                D = C;
                C = B;
                B = A;
                A = (T1 + T2) | 0;
            }
            // Add the compressed chunk to the current hash value
            A = (A + this.A) | 0;
            B = (B + this.B) | 0;
            C = (C + this.C) | 0;
            D = (D + this.D) | 0;
            E = (E + this.E) | 0;
            F = (F + this.F) | 0;
            G = (G + this.G) | 0;
            H = (H + this.H) | 0;
            this.set(A, B, C, D, E, F, G, H);
        }
        roundClean() {
            SHA256_W$3.fill(0);
        }
        destroy() {
            this.set(0, 0, 0, 0, 0, 0, 0, 0);
            this.buffer.fill(0);
        }
    };
    // Constants from https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
    let SHA224$3 = class SHA224 extends SHA256$3 {
        constructor() {
            super();
            this.A = 0xc1059ed8 | 0;
            this.B = 0x367cd507 | 0;
            this.C = 0x3070dd17 | 0;
            this.D = 0xf70e5939 | 0;
            this.E = 0xffc00b31 | 0;
            this.F = 0x68581511 | 0;
            this.G = 0x64f98fa7 | 0;
            this.H = 0xbefa4fa4 | 0;
            this.outputLen = 28;
        }
    };
    /**
     * SHA2-256 hash function
     * @param message - data that would be hashed
     */
    const sha256$3 = wrapConstructor$2(() => new SHA256$3());
    wrapConstructor$2(() => new SHA224$3());

    /*! scure-base - MIT License (c) 2022 Paul Miller (paulmillr.com) */
    function assertNumber(n) {
        if (!Number.isSafeInteger(n))
            throw new Error(`Wrong integer: ${n}`);
    }
    function chain(...args) {
        const wrap = (a, b) => (c) => a(b(c));
        const encode = Array.from(args)
            .reverse()
            .reduce((acc, i) => (acc ? wrap(acc, i.encode) : i.encode), undefined);
        const decode = args.reduce((acc, i) => (acc ? wrap(acc, i.decode) : i.decode), undefined);
        return { encode, decode };
    }
    function alphabet(alphabet) {
        return {
            encode: (digits) => {
                if (!Array.isArray(digits) || (digits.length && typeof digits[0] !== 'number'))
                    throw new Error('alphabet.encode input should be an array of numbers');
                return digits.map((i) => {
                    assertNumber(i);
                    if (i < 0 || i >= alphabet.length)
                        throw new Error(`Digit index outside alphabet: ${i} (alphabet: ${alphabet.length})`);
                    return alphabet[i];
                });
            },
            decode: (input) => {
                if (!Array.isArray(input) || (input.length && typeof input[0] !== 'string'))
                    throw new Error('alphabet.decode input should be array of strings');
                return input.map((letter) => {
                    if (typeof letter !== 'string')
                        throw new Error(`alphabet.decode: not string element=${letter}`);
                    const index = alphabet.indexOf(letter);
                    if (index === -1)
                        throw new Error(`Unknown letter: "${letter}". Allowed: ${alphabet}`);
                    return index;
                });
            },
        };
    }
    function join(separator = '') {
        if (typeof separator !== 'string')
            throw new Error('join separator should be string');
        return {
            encode: (from) => {
                if (!Array.isArray(from) || (from.length && typeof from[0] !== 'string'))
                    throw new Error('join.encode input should be array of strings');
                for (let i of from)
                    if (typeof i !== 'string')
                        throw new Error(`join.encode: non-string input=${i}`);
                return from.join(separator);
            },
            decode: (to) => {
                if (typeof to !== 'string')
                    throw new Error('join.decode input should be string');
                return to.split(separator);
            },
        };
    }
    function padding(bits, chr = '=') {
        assertNumber(bits);
        if (typeof chr !== 'string')
            throw new Error('padding chr should be string');
        return {
            encode(data) {
                if (!Array.isArray(data) || (data.length && typeof data[0] !== 'string'))
                    throw new Error('padding.encode input should be array of strings');
                for (let i of data)
                    if (typeof i !== 'string')
                        throw new Error(`padding.encode: non-string input=${i}`);
                while ((data.length * bits) % 8)
                    data.push(chr);
                return data;
            },
            decode(input) {
                if (!Array.isArray(input) || (input.length && typeof input[0] !== 'string'))
                    throw new Error('padding.encode input should be array of strings');
                for (let i of input)
                    if (typeof i !== 'string')
                        throw new Error(`padding.decode: non-string input=${i}`);
                let end = input.length;
                if ((end * bits) % 8)
                    throw new Error('Invalid padding: string should have whole number of bytes');
                for (; end > 0 && input[end - 1] === chr; end--) {
                    if (!(((end - 1) * bits) % 8))
                        throw new Error('Invalid padding: string has too much padding');
                }
                return input.slice(0, end);
            },
        };
    }
    function normalize$1(fn) {
        if (typeof fn !== 'function')
            throw new Error('normalize fn should be function');
        return { encode: (from) => from, decode: (to) => fn(to) };
    }
    function convertRadix(data, from, to) {
        if (from < 2)
            throw new Error(`convertRadix: wrong from=${from}, base cannot be less than 2`);
        if (to < 2)
            throw new Error(`convertRadix: wrong to=${to}, base cannot be less than 2`);
        if (!Array.isArray(data))
            throw new Error('convertRadix: data should be array');
        if (!data.length)
            return [];
        let pos = 0;
        const res = [];
        const digits = Array.from(data);
        digits.forEach((d) => {
            assertNumber(d);
            if (d < 0 || d >= from)
                throw new Error(`Wrong integer: ${d}`);
        });
        while (true) {
            let carry = 0;
            let done = true;
            for (let i = pos; i < digits.length; i++) {
                const digit = digits[i];
                const digitBase = from * carry + digit;
                if (!Number.isSafeInteger(digitBase) ||
                    (from * carry) / from !== carry ||
                    digitBase - digit !== from * carry) {
                    throw new Error('convertRadix: carry overflow');
                }
                carry = digitBase % to;
                digits[i] = Math.floor(digitBase / to);
                if (!Number.isSafeInteger(digits[i]) || digits[i] * to + carry !== digitBase)
                    throw new Error('convertRadix: carry overflow');
                if (!done)
                    continue;
                else if (!digits[i])
                    pos = i;
                else
                    done = false;
            }
            res.push(carry);
            if (done)
                break;
        }
        for (let i = 0; i < data.length - 1 && data[i] === 0; i++)
            res.push(0);
        return res.reverse();
    }
    const gcd = (a, b) => (!b ? a : gcd(b, a % b));
    const radix2carry = (from, to) => from + (to - gcd(from, to));
    function convertRadix2(data, from, to, padding) {
        if (!Array.isArray(data))
            throw new Error('convertRadix2: data should be array');
        if (from <= 0 || from > 32)
            throw new Error(`convertRadix2: wrong from=${from}`);
        if (to <= 0 || to > 32)
            throw new Error(`convertRadix2: wrong to=${to}`);
        if (radix2carry(from, to) > 32) {
            throw new Error(`convertRadix2: carry overflow from=${from} to=${to} carryBits=${radix2carry(from, to)}`);
        }
        let carry = 0;
        let pos = 0;
        const mask = 2 ** to - 1;
        const res = [];
        for (const n of data) {
            assertNumber(n);
            if (n >= 2 ** from)
                throw new Error(`convertRadix2: invalid data word=${n} from=${from}`);
            carry = (carry << from) | n;
            if (pos + from > 32)
                throw new Error(`convertRadix2: carry overflow pos=${pos} from=${from}`);
            pos += from;
            for (; pos >= to; pos -= to)
                res.push(((carry >> (pos - to)) & mask) >>> 0);
            carry &= 2 ** pos - 1;
        }
        carry = (carry << (to - pos)) & mask;
        if (!padding && pos >= from)
            throw new Error('Excess padding');
        if (!padding && carry)
            throw new Error(`Non-zero padding: ${carry}`);
        if (padding && pos > 0)
            res.push(carry >>> 0);
        return res;
    }
    function radix(num) {
        assertNumber(num);
        return {
            encode: (bytes) => {
                if (!(bytes instanceof Uint8Array))
                    throw new Error('radix.encode input should be Uint8Array');
                return convertRadix(Array.from(bytes), 2 ** 8, num);
            },
            decode: (digits) => {
                if (!Array.isArray(digits) || (digits.length && typeof digits[0] !== 'number'))
                    throw new Error('radix.decode input should be array of strings');
                return Uint8Array.from(convertRadix(digits, num, 2 ** 8));
            },
        };
    }
    function radix2(bits, revPadding = false) {
        assertNumber(bits);
        if (bits <= 0 || bits > 32)
            throw new Error('radix2: bits should be in (0..32]');
        if (radix2carry(8, bits) > 32 || radix2carry(bits, 8) > 32)
            throw new Error('radix2: carry overflow');
        return {
            encode: (bytes) => {
                if (!(bytes instanceof Uint8Array))
                    throw new Error('radix2.encode input should be Uint8Array');
                return convertRadix2(Array.from(bytes), 8, bits, !revPadding);
            },
            decode: (digits) => {
                if (!Array.isArray(digits) || (digits.length && typeof digits[0] !== 'number'))
                    throw new Error('radix2.decode input should be array of strings');
                return Uint8Array.from(convertRadix2(digits, bits, 8, revPadding));
            },
        };
    }
    function unsafeWrapper(fn) {
        if (typeof fn !== 'function')
            throw new Error('unsafeWrapper fn should be function');
        return function (...args) {
            try {
                return fn.apply(null, args);
            }
            catch (e) { }
        };
    }
    function checksum(len, fn) {
        assertNumber(len);
        if (typeof fn !== 'function')
            throw new Error('checksum fn should be function');
        return {
            encode(data) {
                if (!(data instanceof Uint8Array))
                    throw new Error('checksum.encode: input should be Uint8Array');
                const checksum = fn(data).slice(0, len);
                const res = new Uint8Array(data.length + len);
                res.set(data);
                res.set(checksum, data.length);
                return res;
            },
            decode(data) {
                if (!(data instanceof Uint8Array))
                    throw new Error('checksum.decode: input should be Uint8Array');
                const payload = data.slice(0, -len);
                const newChecksum = fn(payload).slice(0, len);
                const oldChecksum = data.slice(-len);
                for (let i = 0; i < len; i++)
                    if (newChecksum[i] !== oldChecksum[i])
                        throw new Error('Invalid checksum');
                return payload;
            },
        };
    }
    const base16 = chain(radix2(4), alphabet('0123456789ABCDEF'), join(''));
    const base32 = chain(radix2(5), alphabet('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'), padding(5), join(''));
    chain(radix2(5), alphabet('0123456789ABCDEFGHIJKLMNOPQRSTUV'), padding(5), join(''));
    chain(radix2(5), alphabet('0123456789ABCDEFGHJKMNPQRSTVWXYZ'), join(''), normalize$1((s) => s.toUpperCase().replace(/O/g, '0').replace(/[IL]/g, '1')));
    const base64 = chain(radix2(6), alphabet('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'), padding(6), join(''));
    const base64url = chain(radix2(6), alphabet('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'), padding(6), join(''));
    const genBase58 = (abc) => chain(radix(58), alphabet(abc), join(''));
    const base58 = genBase58('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz');
    genBase58('123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ');
    genBase58('rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz');
    const XMR_BLOCK_LEN = [0, 2, 3, 5, 6, 7, 9, 10, 11];
    const base58xmr = {
        encode(data) {
            let res = '';
            for (let i = 0; i < data.length; i += 8) {
                const block = data.subarray(i, i + 8);
                res += base58.encode(block).padStart(XMR_BLOCK_LEN[block.length], '1');
            }
            return res;
        },
        decode(str) {
            let res = [];
            for (let i = 0; i < str.length; i += 11) {
                const slice = str.slice(i, i + 11);
                const blockLen = XMR_BLOCK_LEN.indexOf(slice.length);
                const block = base58.decode(slice);
                for (let j = 0; j < block.length - blockLen; j++) {
                    if (block[j] !== 0)
                        throw new Error('base58xmr: wrong padding');
                }
                res = res.concat(Array.from(block.slice(block.length - blockLen)));
            }
            return Uint8Array.from(res);
        },
    };
    const base58check$1 = (sha256) => chain(checksum(4, (data) => sha256(sha256(data))), base58);
    const BECH_ALPHABET = chain(alphabet('qpzry9x8gf2tvdw0s3jn54khce6mua7l'), join(''));
    const POLYMOD_GENERATORS = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    function bech32Polymod(pre) {
        const b = pre >> 25;
        let chk = (pre & 0x1ffffff) << 5;
        for (let i = 0; i < POLYMOD_GENERATORS.length; i++) {
            if (((b >> i) & 1) === 1)
                chk ^= POLYMOD_GENERATORS[i];
        }
        return chk;
    }
    function bechChecksum(prefix, words, encodingConst = 1) {
        const len = prefix.length;
        let chk = 1;
        for (let i = 0; i < len; i++) {
            const c = prefix.charCodeAt(i);
            if (c < 33 || c > 126)
                throw new Error(`Invalid prefix (${prefix})`);
            chk = bech32Polymod(chk) ^ (c >> 5);
        }
        chk = bech32Polymod(chk);
        for (let i = 0; i < len; i++)
            chk = bech32Polymod(chk) ^ (prefix.charCodeAt(i) & 0x1f);
        for (let v of words)
            chk = bech32Polymod(chk) ^ v;
        for (let i = 0; i < 6; i++)
            chk = bech32Polymod(chk);
        chk ^= encodingConst;
        return BECH_ALPHABET.encode(convertRadix2([chk % 2 ** 30], 30, 5, false));
    }
    function genBech32(encoding) {
        const ENCODING_CONST = encoding === 'bech32' ? 1 : 0x2bc830a3;
        const _words = radix2(5);
        const fromWords = _words.decode;
        const toWords = _words.encode;
        const fromWordsUnsafe = unsafeWrapper(fromWords);
        function encode(prefix, words, limit = 90) {
            if (typeof prefix !== 'string')
                throw new Error(`bech32.encode prefix should be string, not ${typeof prefix}`);
            if (!Array.isArray(words) || (words.length && typeof words[0] !== 'number'))
                throw new Error(`bech32.encode words should be array of numbers, not ${typeof words}`);
            const actualLength = prefix.length + 7 + words.length;
            if (limit !== false && actualLength > limit)
                throw new TypeError(`Length ${actualLength} exceeds limit ${limit}`);
            prefix = prefix.toLowerCase();
            return `${prefix}1${BECH_ALPHABET.encode(words)}${bechChecksum(prefix, words, ENCODING_CONST)}`;
        }
        function decode(str, limit = 90) {
            if (typeof str !== 'string')
                throw new Error(`bech32.decode input should be string, not ${typeof str}`);
            if (str.length < 8 || (limit !== false && str.length > limit))
                throw new TypeError(`Wrong string length: ${str.length} (${str}). Expected (8..${limit})`);
            const lowered = str.toLowerCase();
            if (str !== lowered && str !== str.toUpperCase())
                throw new Error(`String must be lowercase or uppercase`);
            str = lowered;
            const sepIndex = str.lastIndexOf('1');
            if (sepIndex === 0 || sepIndex === -1)
                throw new Error(`Letter "1" must be present between prefix and data only`);
            const prefix = str.slice(0, sepIndex);
            const _words = str.slice(sepIndex + 1);
            if (_words.length < 6)
                throw new Error('Data must be at least 6 characters long');
            const words = BECH_ALPHABET.decode(_words).slice(0, -6);
            const sum = bechChecksum(prefix, words, ENCODING_CONST);
            if (!_words.endsWith(sum))
                throw new Error(`Invalid checksum in ${str}: expected "${sum}"`);
            return { prefix, words };
        }
        const decodeUnsafe = unsafeWrapper(decode);
        function decodeToBytes(str) {
            const { prefix, words } = decode(str, false);
            return { prefix, words, bytes: fromWords(words) };
        }
        return { encode, decode, decodeToBytes, decodeUnsafe, fromWords, fromWordsUnsafe, toWords };
    }
    const bech32 = genBech32('bech32');
    genBech32('bech32m');
    const utf8 = {
        encode: (data) => new TextDecoder().decode(data),
        decode: (str) => new TextEncoder().encode(str),
    };
    const hex = chain(radix2(4), alphabet('0123456789abcdef'), join(''), normalize$1((s) => {
        if (typeof s !== 'string' || s.length % 2)
            throw new TypeError(`hex.decode: expected string, got ${typeof s} with length ${s.length}`);
        return s.toLowerCase();
    }));
    const CODERS = {
        utf8, hex, base16, base32, base64, base64url, base58, base58xmr
    };
`Invalid encoding type. Available types: ${Object.keys(CODERS).join(', ')}`;

    var english = {};

    Object.defineProperty(english, "__esModule", { value: true });
    var wordlist = english.wordlist = void 0;
    wordlist = english.wordlist = `abandon
ability
able
about
above
absent
absorb
abstract
absurd
abuse
access
accident
account
accuse
achieve
acid
acoustic
acquire
across
act
action
actor
actress
actual
adapt
add
addict
address
adjust
admit
adult
advance
advice
aerobic
affair
afford
afraid
again
age
agent
agree
ahead
aim
air
airport
aisle
alarm
album
alcohol
alert
alien
all
alley
allow
almost
alone
alpha
already
also
alter
always
amateur
amazing
among
amount
amused
analyst
anchor
ancient
anger
angle
angry
animal
ankle
announce
annual
another
answer
antenna
antique
anxiety
any
apart
apology
appear
apple
approve
april
arch
arctic
area
arena
argue
arm
armed
armor
army
around
arrange
arrest
arrive
arrow
art
artefact
artist
artwork
ask
aspect
assault
asset
assist
assume
asthma
athlete
atom
attack
attend
attitude
attract
auction
audit
august
aunt
author
auto
autumn
average
avocado
avoid
awake
aware
away
awesome
awful
awkward
axis
baby
bachelor
bacon
badge
bag
balance
balcony
ball
bamboo
banana
banner
bar
barely
bargain
barrel
base
basic
basket
battle
beach
bean
beauty
because
become
beef
before
begin
behave
behind
believe
below
belt
bench
benefit
best
betray
better
between
beyond
bicycle
bid
bike
bind
biology
bird
birth
bitter
black
blade
blame
blanket
blast
bleak
bless
blind
blood
blossom
blouse
blue
blur
blush
board
boat
body
boil
bomb
bone
bonus
book
boost
border
boring
borrow
boss
bottom
bounce
box
boy
bracket
brain
brand
brass
brave
bread
breeze
brick
bridge
brief
bright
bring
brisk
broccoli
broken
bronze
broom
brother
brown
brush
bubble
buddy
budget
buffalo
build
bulb
bulk
bullet
bundle
bunker
burden
burger
burst
bus
business
busy
butter
buyer
buzz
cabbage
cabin
cable
cactus
cage
cake
call
calm
camera
camp
can
canal
cancel
candy
cannon
canoe
canvas
canyon
capable
capital
captain
car
carbon
card
cargo
carpet
carry
cart
case
cash
casino
castle
casual
cat
catalog
catch
category
cattle
caught
cause
caution
cave
ceiling
celery
cement
census
century
cereal
certain
chair
chalk
champion
change
chaos
chapter
charge
chase
chat
cheap
check
cheese
chef
cherry
chest
chicken
chief
child
chimney
choice
choose
chronic
chuckle
chunk
churn
cigar
cinnamon
circle
citizen
city
civil
claim
clap
clarify
claw
clay
clean
clerk
clever
click
client
cliff
climb
clinic
clip
clock
clog
close
cloth
cloud
clown
club
clump
cluster
clutch
coach
coast
coconut
code
coffee
coil
coin
collect
color
column
combine
come
comfort
comic
common
company
concert
conduct
confirm
congress
connect
consider
control
convince
cook
cool
copper
copy
coral
core
corn
correct
cost
cotton
couch
country
couple
course
cousin
cover
coyote
crack
cradle
craft
cram
crane
crash
crater
crawl
crazy
cream
credit
creek
crew
cricket
crime
crisp
critic
crop
cross
crouch
crowd
crucial
cruel
cruise
crumble
crunch
crush
cry
crystal
cube
culture
cup
cupboard
curious
current
curtain
curve
cushion
custom
cute
cycle
dad
damage
damp
dance
danger
daring
dash
daughter
dawn
day
deal
debate
debris
decade
december
decide
decline
decorate
decrease
deer
defense
define
defy
degree
delay
deliver
demand
demise
denial
dentist
deny
depart
depend
deposit
depth
deputy
derive
describe
desert
design
desk
despair
destroy
detail
detect
develop
device
devote
diagram
dial
diamond
diary
dice
diesel
diet
differ
digital
dignity
dilemma
dinner
dinosaur
direct
dirt
disagree
discover
disease
dish
dismiss
disorder
display
distance
divert
divide
divorce
dizzy
doctor
document
dog
doll
dolphin
domain
donate
donkey
donor
door
dose
double
dove
draft
dragon
drama
drastic
draw
dream
dress
drift
drill
drink
drip
drive
drop
drum
dry
duck
dumb
dune
during
dust
dutch
duty
dwarf
dynamic
eager
eagle
early
earn
earth
easily
east
easy
echo
ecology
economy
edge
edit
educate
effort
egg
eight
either
elbow
elder
electric
elegant
element
elephant
elevator
elite
else
embark
embody
embrace
emerge
emotion
employ
empower
empty
enable
enact
end
endless
endorse
enemy
energy
enforce
engage
engine
enhance
enjoy
enlist
enough
enrich
enroll
ensure
enter
entire
entry
envelope
episode
equal
equip
era
erase
erode
erosion
error
erupt
escape
essay
essence
estate
eternal
ethics
evidence
evil
evoke
evolve
exact
example
excess
exchange
excite
exclude
excuse
execute
exercise
exhaust
exhibit
exile
exist
exit
exotic
expand
expect
expire
explain
expose
express
extend
extra
eye
eyebrow
fabric
face
faculty
fade
faint
faith
fall
false
fame
family
famous
fan
fancy
fantasy
farm
fashion
fat
fatal
father
fatigue
fault
favorite
feature
february
federal
fee
feed
feel
female
fence
festival
fetch
fever
few
fiber
fiction
field
figure
file
film
filter
final
find
fine
finger
finish
fire
firm
first
fiscal
fish
fit
fitness
fix
flag
flame
flash
flat
flavor
flee
flight
flip
float
flock
floor
flower
fluid
flush
fly
foam
focus
fog
foil
fold
follow
food
foot
force
forest
forget
fork
fortune
forum
forward
fossil
foster
found
fox
fragile
frame
frequent
fresh
friend
fringe
frog
front
frost
frown
frozen
fruit
fuel
fun
funny
furnace
fury
future
gadget
gain
galaxy
gallery
game
gap
garage
garbage
garden
garlic
garment
gas
gasp
gate
gather
gauge
gaze
general
genius
genre
gentle
genuine
gesture
ghost
giant
gift
giggle
ginger
giraffe
girl
give
glad
glance
glare
glass
glide
glimpse
globe
gloom
glory
glove
glow
glue
goat
goddess
gold
good
goose
gorilla
gospel
gossip
govern
gown
grab
grace
grain
grant
grape
grass
gravity
great
green
grid
grief
grit
grocery
group
grow
grunt
guard
guess
guide
guilt
guitar
gun
gym
habit
hair
half
hammer
hamster
hand
happy
harbor
hard
harsh
harvest
hat
have
hawk
hazard
head
health
heart
heavy
hedgehog
height
hello
helmet
help
hen
hero
hidden
high
hill
hint
hip
hire
history
hobby
hockey
hold
hole
holiday
hollow
home
honey
hood
hope
horn
horror
horse
hospital
host
hotel
hour
hover
hub
huge
human
humble
humor
hundred
hungry
hunt
hurdle
hurry
hurt
husband
hybrid
ice
icon
idea
identify
idle
ignore
ill
illegal
illness
image
imitate
immense
immune
impact
impose
improve
impulse
inch
include
income
increase
index
indicate
indoor
industry
infant
inflict
inform
inhale
inherit
initial
inject
injury
inmate
inner
innocent
input
inquiry
insane
insect
inside
inspire
install
intact
interest
into
invest
invite
involve
iron
island
isolate
issue
item
ivory
jacket
jaguar
jar
jazz
jealous
jeans
jelly
jewel
job
join
joke
journey
joy
judge
juice
jump
jungle
junior
junk
just
kangaroo
keen
keep
ketchup
key
kick
kid
kidney
kind
kingdom
kiss
kit
kitchen
kite
kitten
kiwi
knee
knife
knock
know
lab
label
labor
ladder
lady
lake
lamp
language
laptop
large
later
latin
laugh
laundry
lava
law
lawn
lawsuit
layer
lazy
leader
leaf
learn
leave
lecture
left
leg
legal
legend
leisure
lemon
lend
length
lens
leopard
lesson
letter
level
liar
liberty
library
license
life
lift
light
like
limb
limit
link
lion
liquid
list
little
live
lizard
load
loan
lobster
local
lock
logic
lonely
long
loop
lottery
loud
lounge
love
loyal
lucky
luggage
lumber
lunar
lunch
luxury
lyrics
machine
mad
magic
magnet
maid
mail
main
major
make
mammal
man
manage
mandate
mango
mansion
manual
maple
marble
march
margin
marine
market
marriage
mask
mass
master
match
material
math
matrix
matter
maximum
maze
meadow
mean
measure
meat
mechanic
medal
media
melody
melt
member
memory
mention
menu
mercy
merge
merit
merry
mesh
message
metal
method
middle
midnight
milk
million
mimic
mind
minimum
minor
minute
miracle
mirror
misery
miss
mistake
mix
mixed
mixture
mobile
model
modify
mom
moment
monitor
monkey
monster
month
moon
moral
more
morning
mosquito
mother
motion
motor
mountain
mouse
move
movie
much
muffin
mule
multiply
muscle
museum
mushroom
music
must
mutual
myself
mystery
myth
naive
name
napkin
narrow
nasty
nation
nature
near
neck
need
negative
neglect
neither
nephew
nerve
nest
net
network
neutral
never
news
next
nice
night
noble
noise
nominee
noodle
normal
north
nose
notable
note
nothing
notice
novel
now
nuclear
number
nurse
nut
oak
obey
object
oblige
obscure
observe
obtain
obvious
occur
ocean
october
odor
off
offer
office
often
oil
okay
old
olive
olympic
omit
once
one
onion
online
only
open
opera
opinion
oppose
option
orange
orbit
orchard
order
ordinary
organ
orient
original
orphan
ostrich
other
outdoor
outer
output
outside
oval
oven
over
own
owner
oxygen
oyster
ozone
pact
paddle
page
pair
palace
palm
panda
panel
panic
panther
paper
parade
parent
park
parrot
party
pass
patch
path
patient
patrol
pattern
pause
pave
payment
peace
peanut
pear
peasant
pelican
pen
penalty
pencil
people
pepper
perfect
permit
person
pet
phone
photo
phrase
physical
piano
picnic
picture
piece
pig
pigeon
pill
pilot
pink
pioneer
pipe
pistol
pitch
pizza
place
planet
plastic
plate
play
please
pledge
pluck
plug
plunge
poem
poet
point
polar
pole
police
pond
pony
pool
popular
portion
position
possible
post
potato
pottery
poverty
powder
power
practice
praise
predict
prefer
prepare
present
pretty
prevent
price
pride
primary
print
priority
prison
private
prize
problem
process
produce
profit
program
project
promote
proof
property
prosper
protect
proud
provide
public
pudding
pull
pulp
pulse
pumpkin
punch
pupil
puppy
purchase
purity
purpose
purse
push
put
puzzle
pyramid
quality
quantum
quarter
question
quick
quit
quiz
quote
rabbit
raccoon
race
rack
radar
radio
rail
rain
raise
rally
ramp
ranch
random
range
rapid
rare
rate
rather
raven
raw
razor
ready
real
reason
rebel
rebuild
recall
receive
recipe
record
recycle
reduce
reflect
reform
refuse
region
regret
regular
reject
relax
release
relief
rely
remain
remember
remind
remove
render
renew
rent
reopen
repair
repeat
replace
report
require
rescue
resemble
resist
resource
response
result
retire
retreat
return
reunion
reveal
review
reward
rhythm
rib
ribbon
rice
rich
ride
ridge
rifle
right
rigid
ring
riot
ripple
risk
ritual
rival
river
road
roast
robot
robust
rocket
romance
roof
rookie
room
rose
rotate
rough
round
route
royal
rubber
rude
rug
rule
run
runway
rural
sad
saddle
sadness
safe
sail
salad
salmon
salon
salt
salute
same
sample
sand
satisfy
satoshi
sauce
sausage
save
say
scale
scan
scare
scatter
scene
scheme
school
science
scissors
scorpion
scout
scrap
screen
script
scrub
sea
search
season
seat
second
secret
section
security
seed
seek
segment
select
sell
seminar
senior
sense
sentence
series
service
session
settle
setup
seven
shadow
shaft
shallow
share
shed
shell
sheriff
shield
shift
shine
ship
shiver
shock
shoe
shoot
shop
short
shoulder
shove
shrimp
shrug
shuffle
shy
sibling
sick
side
siege
sight
sign
silent
silk
silly
silver
similar
simple
since
sing
siren
sister
situate
six
size
skate
sketch
ski
skill
skin
skirt
skull
slab
slam
sleep
slender
slice
slide
slight
slim
slogan
slot
slow
slush
small
smart
smile
smoke
smooth
snack
snake
snap
sniff
snow
soap
soccer
social
sock
soda
soft
solar
soldier
solid
solution
solve
someone
song
soon
sorry
sort
soul
sound
soup
source
south
space
spare
spatial
spawn
speak
special
speed
spell
spend
sphere
spice
spider
spike
spin
spirit
split
spoil
sponsor
spoon
sport
spot
spray
spread
spring
spy
square
squeeze
squirrel
stable
stadium
staff
stage
stairs
stamp
stand
start
state
stay
steak
steel
stem
step
stereo
stick
still
sting
stock
stomach
stone
stool
story
stove
strategy
street
strike
strong
struggle
student
stuff
stumble
style
subject
submit
subway
success
such
sudden
suffer
sugar
suggest
suit
summer
sun
sunny
sunset
super
supply
supreme
sure
surface
surge
surprise
surround
survey
suspect
sustain
swallow
swamp
swap
swarm
swear
sweet
swift
swim
swing
switch
sword
symbol
symptom
syrup
system
table
tackle
tag
tail
talent
talk
tank
tape
target
task
taste
tattoo
taxi
teach
team
tell
ten
tenant
tennis
tent
term
test
text
thank
that
theme
then
theory
there
they
thing
this
thought
three
thrive
throw
thumb
thunder
ticket
tide
tiger
tilt
timber
time
tiny
tip
tired
tissue
title
toast
tobacco
today
toddler
toe
together
toilet
token
tomato
tomorrow
tone
tongue
tonight
tool
tooth
top
topic
topple
torch
tornado
tortoise
toss
total
tourist
toward
tower
town
toy
track
trade
traffic
tragic
train
transfer
trap
trash
travel
tray
treat
tree
trend
trial
tribe
trick
trigger
trim
trip
trophy
trouble
truck
true
truly
trumpet
trust
truth
try
tube
tuition
tumble
tuna
tunnel
turkey
turn
turtle
twelve
twenty
twice
twin
twist
two
type
typical
ugly
umbrella
unable
unaware
uncle
uncover
under
undo
unfair
unfold
unhappy
uniform
unique
unit
universe
unknown
unlock
until
unusual
unveil
update
upgrade
uphold
upon
upper
upset
urban
urge
usage
use
used
useful
useless
usual
utility
vacant
vacuum
vague
valid
valley
valve
van
vanish
vapor
various
vast
vault
vehicle
velvet
vendor
venture
venue
verb
verify
version
very
vessel
veteran
viable
vibrant
vicious
victory
video
view
village
vintage
violin
virtual
virus
visa
visit
visual
vital
vivid
vocal
voice
void
volcano
volume
vote
voyage
wage
wagon
wait
walk
wall
walnut
want
warfare
warm
warrior
wash
wasp
waste
water
wave
way
wealth
weapon
wear
weasel
weather
web
wedding
weekend
weird
welcome
west
wet
whale
what
wheat
wheel
when
where
whip
whisper
wide
width
wife
wild
will
win
window
wine
wing
wink
winner
winter
wire
wisdom
wise
wish
witness
wolf
woman
wonder
wood
wool
word
work
world
worry
worth
wrap
wreck
wrestle
wrist
write
wrong
yard
year
yellow
you
young
youth
zebra
zero
zone
zoo`.split('\n');

    var bip39 = {};

    var _assert = {};

    Object.defineProperty(_assert, "__esModule", { value: true });
    _assert.output = _assert.exists = _assert.hash = _assert.bytes = _assert.bool = _assert.number = void 0;
    function number$2(n) {
        if (!Number.isSafeInteger(n) || n < 0)
            throw new Error(`Wrong positive integer: ${n}`);
    }
    _assert.number = number$2;
    function bool$2(b) {
        if (typeof b !== 'boolean')
            throw new Error(`Expected boolean, not ${b}`);
    }
    _assert.bool = bool$2;
    function bytes$2(b, ...lengths) {
        if (!(b instanceof Uint8Array))
            throw new TypeError('Expected Uint8Array');
        if (lengths.length > 0 && !lengths.includes(b.length))
            throw new TypeError(`Expected Uint8Array of length ${lengths}, not of length=${b.length}`);
    }
    _assert.bytes = bytes$2;
    function hash$2(hash) {
        if (typeof hash !== 'function' || typeof hash.create !== 'function')
            throw new Error('Hash should be wrapped by utils.wrapConstructor');
        number$2(hash.outputLen);
        number$2(hash.blockLen);
    }
    _assert.hash = hash$2;
    function exists$2(instance, checkFinished = true) {
        if (instance.destroyed)
            throw new Error('Hash instance has been destroyed');
        if (checkFinished && instance.finished)
            throw new Error('Hash#digest() has already been called');
    }
    _assert.exists = exists$2;
    function output$2(out, instance) {
        bytes$2(out);
        const min = instance.outputLen;
        if (out.length < min) {
            throw new Error(`digestInto() expects output buffer of length at least ${min}`);
        }
    }
    _assert.output = output$2;
    const assert$3 = {
        number: number$2,
        bool: bool$2,
        bytes: bytes$2,
        hash: hash$2,
        exists: exists$2,
        output: output$2,
    };
    _assert.default = assert$3;

    var pbkdf2$1 = {};

    var hmac$2 = {};

    var utils = {};

    var cryptoBrowser = {};

    Object.defineProperty(cryptoBrowser, "__esModule", { value: true });
    cryptoBrowser.crypto = void 0;
    cryptoBrowser.crypto = {
        node: undefined,
        web: typeof self === 'object' && 'crypto' in self ? self.crypto : undefined,
    };

    (function (exports) {
    	/*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) */
    	Object.defineProperty(exports, "__esModule", { value: true });
    	exports.randomBytes = exports.wrapConstructorWithOpts = exports.wrapConstructor = exports.checkOpts = exports.Hash = exports.concatBytes = exports.toBytes = exports.utf8ToBytes = exports.asyncLoop = exports.nextTick = exports.hexToBytes = exports.bytesToHex = exports.isLE = exports.rotr = exports.createView = exports.u32 = exports.u8 = void 0;
    	// The import here is via the package name. This is to ensure
    	// that exports mapping/resolution does fall into place.
    	const crypto_1 = cryptoBrowser;
    	// Cast array to different type
    	const u8 = (arr) => new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
    	exports.u8 = u8;
    	const u32 = (arr) => new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
    	exports.u32 = u32;
    	// Cast array to view
    	const createView = (arr) => new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
    	exports.createView = createView;
    	// The rotate right (circular right shift) operation for uint32
    	const rotr = (word, shift) => (word << (32 - shift)) | (word >>> shift);
    	exports.rotr = rotr;
    	exports.isLE = new Uint8Array(new Uint32Array([0x11223344]).buffer)[0] === 0x44;
    	// There is almost no big endian hardware, but js typed arrays uses platform specific endianness.
    	// So, just to be sure not to corrupt anything.
    	if (!exports.isLE)
    	    throw new Error('Non little-endian hardware is not supported');
    	const hexes = Array.from({ length: 256 }, (v, i) => i.toString(16).padStart(2, '0'));
    	/**
    	 * @example bytesToHex(Uint8Array.from([0xde, 0xad, 0xbe, 0xef]))
    	 */
    	function bytesToHex(uint8a) {
    	    // pre-caching improves the speed 6x
    	    if (!(uint8a instanceof Uint8Array))
    	        throw new Error('Uint8Array expected');
    	    let hex = '';
    	    for (let i = 0; i < uint8a.length; i++) {
    	        hex += hexes[uint8a[i]];
    	    }
    	    return hex;
    	}
    	exports.bytesToHex = bytesToHex;
    	/**
    	 * @example hexToBytes('deadbeef')
    	 */
    	function hexToBytes(hex) {
    	    if (typeof hex !== 'string') {
    	        throw new TypeError('hexToBytes: expected string, got ' + typeof hex);
    	    }
    	    if (hex.length % 2)
    	        throw new Error('hexToBytes: received invalid unpadded hex');
    	    const array = new Uint8Array(hex.length / 2);
    	    for (let i = 0; i < array.length; i++) {
    	        const j = i * 2;
    	        const hexByte = hex.slice(j, j + 2);
    	        const byte = Number.parseInt(hexByte, 16);
    	        if (Number.isNaN(byte) || byte < 0)
    	            throw new Error('Invalid byte sequence');
    	        array[i] = byte;
    	    }
    	    return array;
    	}
    	exports.hexToBytes = hexToBytes;
    	// There is no setImmediate in browser and setTimeout is slow. However, call to async function will return Promise
    	// which will be fullfiled only on next scheduler queue processing step and this is exactly what we need.
    	const nextTick = async () => { };
    	exports.nextTick = nextTick;
    	// Returns control to thread each 'tick' ms to avoid blocking
    	async function asyncLoop(iters, tick, cb) {
    	    let ts = Date.now();
    	    for (let i = 0; i < iters; i++) {
    	        cb(i);
    	        // Date.now() is not monotonic, so in case if clock goes backwards we return return control too
    	        const diff = Date.now() - ts;
    	        if (diff >= 0 && diff < tick)
    	            continue;
    	        await (0, exports.nextTick)();
    	        ts += diff;
    	    }
    	}
    	exports.asyncLoop = asyncLoop;
    	function utf8ToBytes(str) {
    	    if (typeof str !== 'string') {
    	        throw new TypeError(`utf8ToBytes expected string, got ${typeof str}`);
    	    }
    	    return new TextEncoder().encode(str);
    	}
    	exports.utf8ToBytes = utf8ToBytes;
    	function toBytes(data) {
    	    if (typeof data === 'string')
    	        data = utf8ToBytes(data);
    	    if (!(data instanceof Uint8Array))
    	        throw new TypeError(`Expected input type is Uint8Array (got ${typeof data})`);
    	    return data;
    	}
    	exports.toBytes = toBytes;
    	/**
    	 * Concats Uint8Array-s into one; like `Buffer.concat([buf1, buf2])`
    	 * @example concatBytes(buf1, buf2)
    	 */
    	function concatBytes(...arrays) {
    	    if (!arrays.every((a) => a instanceof Uint8Array))
    	        throw new Error('Uint8Array list expected');
    	    if (arrays.length === 1)
    	        return arrays[0];
    	    const length = arrays.reduce((a, arr) => a + arr.length, 0);
    	    const result = new Uint8Array(length);
    	    for (let i = 0, pad = 0; i < arrays.length; i++) {
    	        const arr = arrays[i];
    	        result.set(arr, pad);
    	        pad += arr.length;
    	    }
    	    return result;
    	}
    	exports.concatBytes = concatBytes;
    	// For runtime check if class implements interface
    	class Hash {
    	    // Safe version that clones internal state
    	    clone() {
    	        return this._cloneInto();
    	    }
    	}
    	exports.Hash = Hash;
    	// Check if object doens't have custom constructor (like Uint8Array/Array)
    	const isPlainObject = (obj) => Object.prototype.toString.call(obj) === '[object Object]' && obj.constructor === Object;
    	function checkOpts(defaults, opts) {
    	    if (opts !== undefined && (typeof opts !== 'object' || !isPlainObject(opts)))
    	        throw new TypeError('Options should be object or undefined');
    	    const merged = Object.assign(defaults, opts);
    	    return merged;
    	}
    	exports.checkOpts = checkOpts;
    	function wrapConstructor(hashConstructor) {
    	    const hashC = (message) => hashConstructor().update(toBytes(message)).digest();
    	    const tmp = hashConstructor();
    	    hashC.outputLen = tmp.outputLen;
    	    hashC.blockLen = tmp.blockLen;
    	    hashC.create = () => hashConstructor();
    	    return hashC;
    	}
    	exports.wrapConstructor = wrapConstructor;
    	function wrapConstructorWithOpts(hashCons) {
    	    const hashC = (msg, opts) => hashCons(opts).update(toBytes(msg)).digest();
    	    const tmp = hashCons({});
    	    hashC.outputLen = tmp.outputLen;
    	    hashC.blockLen = tmp.blockLen;
    	    hashC.create = (opts) => hashCons(opts);
    	    return hashC;
    	}
    	exports.wrapConstructorWithOpts = wrapConstructorWithOpts;
    	/**
    	 * Secure PRNG
    	 */
    	function randomBytes(bytesLength = 32) {
    	    if (crypto_1.crypto.web) {
    	        return crypto_1.crypto.web.getRandomValues(new Uint8Array(bytesLength));
    	    }
    	    else if (crypto_1.crypto.node) {
    	        return new Uint8Array(crypto_1.crypto.node.randomBytes(bytesLength).buffer);
    	    }
    	    else {
    	        throw new Error("The environment doesn't have randomBytes function");
    	    }
    	}
    	exports.randomBytes = randomBytes;
    	
    } (utils));

    (function (exports) {
    	Object.defineProperty(exports, "__esModule", { value: true });
    	exports.hmac = void 0;
    	const _assert_js_1 = _assert;
    	const utils_js_1 = utils;
    	// HMAC (RFC 2104)
    	class HMAC extends utils_js_1.Hash {
    	    constructor(hash, _key) {
    	        super();
    	        this.finished = false;
    	        this.destroyed = false;
    	        _assert_js_1.default.hash(hash);
    	        const key = (0, utils_js_1.toBytes)(_key);
    	        this.iHash = hash.create();
    	        if (typeof this.iHash.update !== 'function')
    	            throw new TypeError('Expected instance of class which extends utils.Hash');
    	        this.blockLen = this.iHash.blockLen;
    	        this.outputLen = this.iHash.outputLen;
    	        const blockLen = this.blockLen;
    	        const pad = new Uint8Array(blockLen);
    	        // blockLen can be bigger than outputLen
    	        pad.set(key.length > blockLen ? hash.create().update(key).digest() : key);
    	        for (let i = 0; i < pad.length; i++)
    	            pad[i] ^= 0x36;
    	        this.iHash.update(pad);
    	        // By doing update (processing of first block) of outer hash here we can re-use it between multiple calls via clone
    	        this.oHash = hash.create();
    	        // Undo internal XOR && apply outer XOR
    	        for (let i = 0; i < pad.length; i++)
    	            pad[i] ^= 0x36 ^ 0x5c;
    	        this.oHash.update(pad);
    	        pad.fill(0);
    	    }
    	    update(buf) {
    	        _assert_js_1.default.exists(this);
    	        this.iHash.update(buf);
    	        return this;
    	    }
    	    digestInto(out) {
    	        _assert_js_1.default.exists(this);
    	        _assert_js_1.default.bytes(out, this.outputLen);
    	        this.finished = true;
    	        this.iHash.digestInto(out);
    	        this.oHash.update(out);
    	        this.oHash.digestInto(out);
    	        this.destroy();
    	    }
    	    digest() {
    	        const out = new Uint8Array(this.oHash.outputLen);
    	        this.digestInto(out);
    	        return out;
    	    }
    	    _cloneInto(to) {
    	        // Create new instance without calling constructor since key already in state and we don't know it.
    	        to || (to = Object.create(Object.getPrototypeOf(this), {}));
    	        const { oHash, iHash, finished, destroyed, blockLen, outputLen } = this;
    	        to = to;
    	        to.finished = finished;
    	        to.destroyed = destroyed;
    	        to.blockLen = blockLen;
    	        to.outputLen = outputLen;
    	        to.oHash = oHash._cloneInto(to.oHash);
    	        to.iHash = iHash._cloneInto(to.iHash);
    	        return to;
    	    }
    	    destroy() {
    	        this.destroyed = true;
    	        this.oHash.destroy();
    	        this.iHash.destroy();
    	    }
    	}
    	/**
    	 * HMAC: RFC2104 message authentication code.
    	 * @param hash - function that would be used e.g. sha256
    	 * @param key - message key
    	 * @param message - message data
    	 */
    	const hmac = (hash, key, message) => new HMAC(hash, key).update(message).digest();
    	exports.hmac = hmac;
    	exports.hmac.create = (hash, key) => new HMAC(hash, key);
    	
    } (hmac$2));

    Object.defineProperty(pbkdf2$1, "__esModule", { value: true });
    pbkdf2$1.pbkdf2Async = pbkdf2$1.pbkdf2 = void 0;
    const _assert_js_1$1 = _assert;
    const hmac_js_1 = hmac$2;
    const utils_js_1$3 = utils;
    // Common prologue and epilogue for sync/async functions
    function pbkdf2Init(hash, _password, _salt, _opts) {
        _assert_js_1$1.default.hash(hash);
        const opts = (0, utils_js_1$3.checkOpts)({ dkLen: 32, asyncTick: 10 }, _opts);
        const { c, dkLen, asyncTick } = opts;
        _assert_js_1$1.default.number(c);
        _assert_js_1$1.default.number(dkLen);
        _assert_js_1$1.default.number(asyncTick);
        if (c < 1)
            throw new Error('PBKDF2: iterations (c) should be >= 1');
        const password = (0, utils_js_1$3.toBytes)(_password);
        const salt = (0, utils_js_1$3.toBytes)(_salt);
        // DK = PBKDF2(PRF, Password, Salt, c, dkLen);
        const DK = new Uint8Array(dkLen);
        // U1 = PRF(Password, Salt + INT_32_BE(i))
        const PRF = hmac_js_1.hmac.create(hash, password);
        const PRFSalt = PRF._cloneInto().update(salt);
        return { c, dkLen, asyncTick, DK, PRF, PRFSalt };
    }
    function pbkdf2Output(PRF, PRFSalt, DK, prfW, u) {
        PRF.destroy();
        PRFSalt.destroy();
        if (prfW)
            prfW.destroy();
        u.fill(0);
        return DK;
    }
    /**
     * PBKDF2-HMAC: RFC 2898 key derivation function
     * @param hash - hash function that would be used e.g. sha256
     * @param password - password from which a derived key is generated
     * @param salt - cryptographic salt
     * @param opts - {c, dkLen} where c is work factor and dkLen is output message size
     */
    function pbkdf2(hash, password, salt, opts) {
        const { c, dkLen, DK, PRF, PRFSalt } = pbkdf2Init(hash, password, salt, opts);
        let prfW; // Working copy
        const arr = new Uint8Array(4);
        const view = (0, utils_js_1$3.createView)(arr);
        const u = new Uint8Array(PRF.outputLen);
        // DK = T1 + T2 + ⋯ + Tdklen/hlen
        for (let ti = 1, pos = 0; pos < dkLen; ti++, pos += PRF.outputLen) {
            // Ti = F(Password, Salt, c, i)
            const Ti = DK.subarray(pos, pos + PRF.outputLen);
            view.setInt32(0, ti, false);
            // F(Password, Salt, c, i) = U1 ^ U2 ^ ⋯ ^ Uc
            // U1 = PRF(Password, Salt + INT_32_BE(i))
            (prfW = PRFSalt._cloneInto(prfW)).update(arr).digestInto(u);
            Ti.set(u.subarray(0, Ti.length));
            for (let ui = 1; ui < c; ui++) {
                // Uc = PRF(Password, Uc−1)
                PRF._cloneInto(prfW).update(u).digestInto(u);
                for (let i = 0; i < Ti.length; i++)
                    Ti[i] ^= u[i];
            }
        }
        return pbkdf2Output(PRF, PRFSalt, DK, prfW, u);
    }
    pbkdf2$1.pbkdf2 = pbkdf2;
    async function pbkdf2Async(hash, password, salt, opts) {
        const { c, dkLen, asyncTick, DK, PRF, PRFSalt } = pbkdf2Init(hash, password, salt, opts);
        let prfW; // Working copy
        const arr = new Uint8Array(4);
        const view = (0, utils_js_1$3.createView)(arr);
        const u = new Uint8Array(PRF.outputLen);
        // DK = T1 + T2 + ⋯ + Tdklen/hlen
        for (let ti = 1, pos = 0; pos < dkLen; ti++, pos += PRF.outputLen) {
            // Ti = F(Password, Salt, c, i)
            const Ti = DK.subarray(pos, pos + PRF.outputLen);
            view.setInt32(0, ti, false);
            // F(Password, Salt, c, i) = U1 ^ U2 ^ ⋯ ^ Uc
            // U1 = PRF(Password, Salt + INT_32_BE(i))
            (prfW = PRFSalt._cloneInto(prfW)).update(arr).digestInto(u);
            Ti.set(u.subarray(0, Ti.length));
            await (0, utils_js_1$3.asyncLoop)(c - 1, asyncTick, (i) => {
                // Uc = PRF(Password, Uc−1)
                PRF._cloneInto(prfW).update(u).digestInto(u);
                for (let i = 0; i < Ti.length; i++)
                    Ti[i] ^= u[i];
            });
        }
        return pbkdf2Output(PRF, PRFSalt, DK, prfW, u);
    }
    pbkdf2$1.pbkdf2Async = pbkdf2Async;

    var sha256$2 = {};

    var _sha2 = {};

    Object.defineProperty(_sha2, "__esModule", { value: true });
    _sha2.SHA2 = void 0;
    const _assert_js_1 = _assert;
    const utils_js_1$2 = utils;
    // Polyfill for Safari 14
    function setBigUint64$2(view, byteOffset, value, isLE) {
        if (typeof view.setBigUint64 === 'function')
            return view.setBigUint64(byteOffset, value, isLE);
        const _32n = BigInt(32);
        const _u32_max = BigInt(0xffffffff);
        const wh = Number((value >> _32n) & _u32_max);
        const wl = Number(value & _u32_max);
        const h = isLE ? 4 : 0;
        const l = isLE ? 0 : 4;
        view.setUint32(byteOffset + h, wh, isLE);
        view.setUint32(byteOffset + l, wl, isLE);
    }
    // Base SHA2 class (RFC 6234)
    let SHA2$2 = class SHA2 extends utils_js_1$2.Hash {
        constructor(blockLen, outputLen, padOffset, isLE) {
            super();
            this.blockLen = blockLen;
            this.outputLen = outputLen;
            this.padOffset = padOffset;
            this.isLE = isLE;
            this.finished = false;
            this.length = 0;
            this.pos = 0;
            this.destroyed = false;
            this.buffer = new Uint8Array(blockLen);
            this.view = (0, utils_js_1$2.createView)(this.buffer);
        }
        update(data) {
            _assert_js_1.default.exists(this);
            const { view, buffer, blockLen } = this;
            data = (0, utils_js_1$2.toBytes)(data);
            const len = data.length;
            for (let pos = 0; pos < len;) {
                const take = Math.min(blockLen - this.pos, len - pos);
                // Fast path: we have at least one block in input, cast it to view and process
                if (take === blockLen) {
                    const dataView = (0, utils_js_1$2.createView)(data);
                    for (; blockLen <= len - pos; pos += blockLen)
                        this.process(dataView, pos);
                    continue;
                }
                buffer.set(data.subarray(pos, pos + take), this.pos);
                this.pos += take;
                pos += take;
                if (this.pos === blockLen) {
                    this.process(view, 0);
                    this.pos = 0;
                }
            }
            this.length += data.length;
            this.roundClean();
            return this;
        }
        digestInto(out) {
            _assert_js_1.default.exists(this);
            _assert_js_1.default.output(out, this);
            this.finished = true;
            // Padding
            // We can avoid allocation of buffer for padding completely if it
            // was previously not allocated here. But it won't change performance.
            const { buffer, view, blockLen, isLE } = this;
            let { pos } = this;
            // append the bit '1' to the message
            buffer[pos++] = 0b10000000;
            this.buffer.subarray(pos).fill(0);
            // we have less than padOffset left in buffer, so we cannot put length in current block, need process it and pad again
            if (this.padOffset > blockLen - pos) {
                this.process(view, 0);
                pos = 0;
            }
            // Pad until full block byte with zeros
            for (let i = pos; i < blockLen; i++)
                buffer[i] = 0;
            // Note: sha512 requires length to be 128bit integer, but length in JS will overflow before that
            // You need to write around 2 exabytes (u64_max / 8 / (1024**6)) for this to happen.
            // So we just write lowest 64 bits of that value.
            setBigUint64$2(view, blockLen - 8, BigInt(this.length * 8), isLE);
            this.process(view, 0);
            const oview = (0, utils_js_1$2.createView)(out);
            const len = this.outputLen;
            // NOTE: we do division by 4 later, which should be fused in single op with modulo by JIT
            if (len % 4)
                throw new Error('_sha2: outputLen should be aligned to 32bit');
            const outLen = len / 4;
            const state = this.get();
            if (outLen > state.length)
                throw new Error('_sha2: outputLen bigger than state');
            for (let i = 0; i < outLen; i++)
                oview.setUint32(4 * i, state[i], isLE);
        }
        digest() {
            const { buffer, outputLen } = this;
            this.digestInto(buffer);
            const res = buffer.slice(0, outputLen);
            this.destroy();
            return res;
        }
        _cloneInto(to) {
            to || (to = new this.constructor());
            to.set(...this.get());
            const { blockLen, buffer, length, finished, destroyed, pos } = this;
            to.length = length;
            to.pos = pos;
            to.finished = finished;
            to.destroyed = destroyed;
            if (length % blockLen)
                to.buffer.set(buffer);
            return to;
        }
    };
    _sha2.SHA2 = SHA2$2;

    Object.defineProperty(sha256$2, "__esModule", { value: true });
    sha256$2.sha224 = sha256$2.sha256 = void 0;
    const _sha2_js_1$1 = _sha2;
    const utils_js_1$1 = utils;
    // Choice: a ? b : c
    const Chi$2 = (a, b, c) => (a & b) ^ (~a & c);
    // Majority function, true if any two inpust is true
    const Maj$2 = (a, b, c) => (a & b) ^ (a & c) ^ (b & c);
    // Round constants:
    // first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311)
    // prettier-ignore
    const SHA256_K$2 = new Uint32Array([
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]);
    // Initial state (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
    // prettier-ignore
    const IV$2 = new Uint32Array([
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]);
    // Temporary buffer, not used to store anything between runs
    // Named this way because it matches specification.
    const SHA256_W$2 = new Uint32Array(64);
    let SHA256$2 = class SHA256 extends _sha2_js_1$1.SHA2 {
        constructor() {
            super(64, 32, 8, false);
            // We cannot use array here since array allows indexing by variable
            // which means optimizer/compiler cannot use registers.
            this.A = IV$2[0] | 0;
            this.B = IV$2[1] | 0;
            this.C = IV$2[2] | 0;
            this.D = IV$2[3] | 0;
            this.E = IV$2[4] | 0;
            this.F = IV$2[5] | 0;
            this.G = IV$2[6] | 0;
            this.H = IV$2[7] | 0;
        }
        get() {
            const { A, B, C, D, E, F, G, H } = this;
            return [A, B, C, D, E, F, G, H];
        }
        // prettier-ignore
        set(A, B, C, D, E, F, G, H) {
            this.A = A | 0;
            this.B = B | 0;
            this.C = C | 0;
            this.D = D | 0;
            this.E = E | 0;
            this.F = F | 0;
            this.G = G | 0;
            this.H = H | 0;
        }
        process(view, offset) {
            // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array
            for (let i = 0; i < 16; i++, offset += 4)
                SHA256_W$2[i] = view.getUint32(offset, false);
            for (let i = 16; i < 64; i++) {
                const W15 = SHA256_W$2[i - 15];
                const W2 = SHA256_W$2[i - 2];
                const s0 = (0, utils_js_1$1.rotr)(W15, 7) ^ (0, utils_js_1$1.rotr)(W15, 18) ^ (W15 >>> 3);
                const s1 = (0, utils_js_1$1.rotr)(W2, 17) ^ (0, utils_js_1$1.rotr)(W2, 19) ^ (W2 >>> 10);
                SHA256_W$2[i] = (s1 + SHA256_W$2[i - 7] + s0 + SHA256_W$2[i - 16]) | 0;
            }
            // Compression function main loop, 64 rounds
            let { A, B, C, D, E, F, G, H } = this;
            for (let i = 0; i < 64; i++) {
                const sigma1 = (0, utils_js_1$1.rotr)(E, 6) ^ (0, utils_js_1$1.rotr)(E, 11) ^ (0, utils_js_1$1.rotr)(E, 25);
                const T1 = (H + sigma1 + Chi$2(E, F, G) + SHA256_K$2[i] + SHA256_W$2[i]) | 0;
                const sigma0 = (0, utils_js_1$1.rotr)(A, 2) ^ (0, utils_js_1$1.rotr)(A, 13) ^ (0, utils_js_1$1.rotr)(A, 22);
                const T2 = (sigma0 + Maj$2(A, B, C)) | 0;
                H = G;
                G = F;
                F = E;
                E = (D + T1) | 0;
                D = C;
                C = B;
                B = A;
                A = (T1 + T2) | 0;
            }
            // Add the compressed chunk to the current hash value
            A = (A + this.A) | 0;
            B = (B + this.B) | 0;
            C = (C + this.C) | 0;
            D = (D + this.D) | 0;
            E = (E + this.E) | 0;
            F = (F + this.F) | 0;
            G = (G + this.G) | 0;
            H = (H + this.H) | 0;
            this.set(A, B, C, D, E, F, G, H);
        }
        roundClean() {
            SHA256_W$2.fill(0);
        }
        destroy() {
            this.set(0, 0, 0, 0, 0, 0, 0, 0);
            this.buffer.fill(0);
        }
    };
    // Constants from https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
    let SHA224$2 = class SHA224 extends SHA256$2 {
        constructor() {
            super();
            this.A = 0xc1059ed8 | 0;
            this.B = 0x367cd507 | 0;
            this.C = 0x3070dd17 | 0;
            this.D = 0xf70e5939 | 0;
            this.E = 0xffc00b31 | 0;
            this.F = 0x68581511 | 0;
            this.G = 0x64f98fa7 | 0;
            this.H = 0xbefa4fa4 | 0;
            this.outputLen = 28;
        }
    };
    /**
     * SHA2-256 hash function
     * @param message - data that would be hashed
     */
    sha256$2.sha256 = (0, utils_js_1$1.wrapConstructor)(() => new SHA256$2());
    sha256$2.sha224 = (0, utils_js_1$1.wrapConstructor)(() => new SHA224$2());

    var sha512$1 = {};

    var _u64 = {};

    (function (exports) {
    	Object.defineProperty(exports, "__esModule", { value: true });
    	exports.add = exports.toBig = exports.split = exports.fromBig = void 0;
    	const U32_MASK64 = BigInt(2 ** 32 - 1);
    	const _32n = BigInt(32);
    	// We are not using BigUint64Array, because they are extremely slow as per 2022
    	function fromBig(n, le = false) {
    	    if (le)
    	        return { h: Number(n & U32_MASK64), l: Number((n >> _32n) & U32_MASK64) };
    	    return { h: Number((n >> _32n) & U32_MASK64) | 0, l: Number(n & U32_MASK64) | 0 };
    	}
    	exports.fromBig = fromBig;
    	function split(lst, le = false) {
    	    let Ah = new Uint32Array(lst.length);
    	    let Al = new Uint32Array(lst.length);
    	    for (let i = 0; i < lst.length; i++) {
    	        const { h, l } = fromBig(lst[i], le);
    	        [Ah[i], Al[i]] = [h, l];
    	    }
    	    return [Ah, Al];
    	}
    	exports.split = split;
    	const toBig = (h, l) => (BigInt(h >>> 0) << _32n) | BigInt(l >>> 0);
    	exports.toBig = toBig;
    	// for Shift in [0, 32)
    	const shrSH = (h, l, s) => h >>> s;
    	const shrSL = (h, l, s) => (h << (32 - s)) | (l >>> s);
    	// Right rotate for Shift in [1, 32)
    	const rotrSH = (h, l, s) => (h >>> s) | (l << (32 - s));
    	const rotrSL = (h, l, s) => (h << (32 - s)) | (l >>> s);
    	// Right rotate for Shift in (32, 64), NOTE: 32 is special case.
    	const rotrBH = (h, l, s) => (h << (64 - s)) | (l >>> (s - 32));
    	const rotrBL = (h, l, s) => (h >>> (s - 32)) | (l << (64 - s));
    	// Right rotate for shift===32 (just swaps l&h)
    	const rotr32H = (h, l) => l;
    	const rotr32L = (h, l) => h;
    	// Left rotate for Shift in [1, 32)
    	const rotlSH = (h, l, s) => (h << s) | (l >>> (32 - s));
    	const rotlSL = (h, l, s) => (l << s) | (h >>> (32 - s));
    	// Left rotate for Shift in (32, 64), NOTE: 32 is special case.
    	const rotlBH = (h, l, s) => (l << (s - 32)) | (h >>> (64 - s));
    	const rotlBL = (h, l, s) => (h << (s - 32)) | (l >>> (64 - s));
    	// JS uses 32-bit signed integers for bitwise operations which means we cannot
    	// simple take carry out of low bit sum by shift, we need to use division.
    	// Removing "export" has 5% perf penalty -_-
    	function add(Ah, Al, Bh, Bl) {
    	    const l = (Al >>> 0) + (Bl >>> 0);
    	    return { h: (Ah + Bh + ((l / 2 ** 32) | 0)) | 0, l: l | 0 };
    	}
    	exports.add = add;
    	// Addition with more than 2 elements
    	const add3L = (Al, Bl, Cl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0);
    	const add3H = (low, Ah, Bh, Ch) => (Ah + Bh + Ch + ((low / 2 ** 32) | 0)) | 0;
    	const add4L = (Al, Bl, Cl, Dl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0);
    	const add4H = (low, Ah, Bh, Ch, Dh) => (Ah + Bh + Ch + Dh + ((low / 2 ** 32) | 0)) | 0;
    	const add5L = (Al, Bl, Cl, Dl, El) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0) + (El >>> 0);
    	const add5H = (low, Ah, Bh, Ch, Dh, Eh) => (Ah + Bh + Ch + Dh + Eh + ((low / 2 ** 32) | 0)) | 0;
    	// prettier-ignore
    	const u64 = {
    	    fromBig, split, toBig: exports.toBig,
    	    shrSH, shrSL,
    	    rotrSH, rotrSL, rotrBH, rotrBL,
    	    rotr32H, rotr32L,
    	    rotlSH, rotlSL, rotlBH, rotlBL,
    	    add, add3L, add3H, add4L, add4H, add5H, add5L,
    	};
    	exports.default = u64;
    	
    } (_u64));

    Object.defineProperty(sha512$1, "__esModule", { value: true });
    sha512$1.sha384 = sha512$1.sha512_256 = sha512$1.sha512_224 = sha512$1.sha512 = sha512$1.SHA512 = void 0;
    const _sha2_js_1 = _sha2;
    const _u64_js_1 = _u64;
    const utils_js_1 = utils;
    // Round contants (first 32 bits of the fractional parts of the cube roots of the first 80 primes 2..409):
    // prettier-ignore
    const [SHA512_Kh$1, SHA512_Kl$1] = _u64_js_1.default.split([
        '0x428a2f98d728ae22', '0x7137449123ef65cd', '0xb5c0fbcfec4d3b2f', '0xe9b5dba58189dbbc',
        '0x3956c25bf348b538', '0x59f111f1b605d019', '0x923f82a4af194f9b', '0xab1c5ed5da6d8118',
        '0xd807aa98a3030242', '0x12835b0145706fbe', '0x243185be4ee4b28c', '0x550c7dc3d5ffb4e2',
        '0x72be5d74f27b896f', '0x80deb1fe3b1696b1', '0x9bdc06a725c71235', '0xc19bf174cf692694',
        '0xe49b69c19ef14ad2', '0xefbe4786384f25e3', '0x0fc19dc68b8cd5b5', '0x240ca1cc77ac9c65',
        '0x2de92c6f592b0275', '0x4a7484aa6ea6e483', '0x5cb0a9dcbd41fbd4', '0x76f988da831153b5',
        '0x983e5152ee66dfab', '0xa831c66d2db43210', '0xb00327c898fb213f', '0xbf597fc7beef0ee4',
        '0xc6e00bf33da88fc2', '0xd5a79147930aa725', '0x06ca6351e003826f', '0x142929670a0e6e70',
        '0x27b70a8546d22ffc', '0x2e1b21385c26c926', '0x4d2c6dfc5ac42aed', '0x53380d139d95b3df',
        '0x650a73548baf63de', '0x766a0abb3c77b2a8', '0x81c2c92e47edaee6', '0x92722c851482353b',
        '0xa2bfe8a14cf10364', '0xa81a664bbc423001', '0xc24b8b70d0f89791', '0xc76c51a30654be30',
        '0xd192e819d6ef5218', '0xd69906245565a910', '0xf40e35855771202a', '0x106aa07032bbd1b8',
        '0x19a4c116b8d2d0c8', '0x1e376c085141ab53', '0x2748774cdf8eeb99', '0x34b0bcb5e19b48a8',
        '0x391c0cb3c5c95a63', '0x4ed8aa4ae3418acb', '0x5b9cca4f7763e373', '0x682e6ff3d6b2b8a3',
        '0x748f82ee5defb2fc', '0x78a5636f43172f60', '0x84c87814a1f0ab72', '0x8cc702081a6439ec',
        '0x90befffa23631e28', '0xa4506cebde82bde9', '0xbef9a3f7b2c67915', '0xc67178f2e372532b',
        '0xca273eceea26619c', '0xd186b8c721c0c207', '0xeada7dd6cde0eb1e', '0xf57d4f7fee6ed178',
        '0x06f067aa72176fba', '0x0a637dc5a2c898a6', '0x113f9804bef90dae', '0x1b710b35131c471b',
        '0x28db77f523047d84', '0x32caab7b40c72493', '0x3c9ebe0a15c9bebc', '0x431d67c49c100d4c',
        '0x4cc5d4becb3e42b6', '0x597f299cfc657e2a', '0x5fcb6fab3ad6faec', '0x6c44198c4a475817'
    ].map(n => BigInt(n)));
    // Temporary buffer, not used to store anything between runs
    const SHA512_W_H$1 = new Uint32Array(80);
    const SHA512_W_L$1 = new Uint32Array(80);
    let SHA512$1 = class SHA512 extends _sha2_js_1.SHA2 {
        constructor() {
            super(128, 64, 16, false);
            // We cannot use array here since array allows indexing by variable which means optimizer/compiler cannot use registers.
            // Also looks cleaner and easier to verify with spec.
            // Initial state (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
            // h -- high 32 bits, l -- low 32 bits
            this.Ah = 0x6a09e667 | 0;
            this.Al = 0xf3bcc908 | 0;
            this.Bh = 0xbb67ae85 | 0;
            this.Bl = 0x84caa73b | 0;
            this.Ch = 0x3c6ef372 | 0;
            this.Cl = 0xfe94f82b | 0;
            this.Dh = 0xa54ff53a | 0;
            this.Dl = 0x5f1d36f1 | 0;
            this.Eh = 0x510e527f | 0;
            this.El = 0xade682d1 | 0;
            this.Fh = 0x9b05688c | 0;
            this.Fl = 0x2b3e6c1f | 0;
            this.Gh = 0x1f83d9ab | 0;
            this.Gl = 0xfb41bd6b | 0;
            this.Hh = 0x5be0cd19 | 0;
            this.Hl = 0x137e2179 | 0;
        }
        // prettier-ignore
        get() {
            const { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
            return [Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl];
        }
        // prettier-ignore
        set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl) {
            this.Ah = Ah | 0;
            this.Al = Al | 0;
            this.Bh = Bh | 0;
            this.Bl = Bl | 0;
            this.Ch = Ch | 0;
            this.Cl = Cl | 0;
            this.Dh = Dh | 0;
            this.Dl = Dl | 0;
            this.Eh = Eh | 0;
            this.El = El | 0;
            this.Fh = Fh | 0;
            this.Fl = Fl | 0;
            this.Gh = Gh | 0;
            this.Gl = Gl | 0;
            this.Hh = Hh | 0;
            this.Hl = Hl | 0;
        }
        process(view, offset) {
            // Extend the first 16 words into the remaining 64 words w[16..79] of the message schedule array
            for (let i = 0; i < 16; i++, offset += 4) {
                SHA512_W_H$1[i] = view.getUint32(offset);
                SHA512_W_L$1[i] = view.getUint32((offset += 4));
            }
            for (let i = 16; i < 80; i++) {
                // s0 := (w[i-15] rightrotate 1) xor (w[i-15] rightrotate 8) xor (w[i-15] rightshift 7)
                const W15h = SHA512_W_H$1[i - 15] | 0;
                const W15l = SHA512_W_L$1[i - 15] | 0;
                const s0h = _u64_js_1.default.rotrSH(W15h, W15l, 1) ^ _u64_js_1.default.rotrSH(W15h, W15l, 8) ^ _u64_js_1.default.shrSH(W15h, W15l, 7);
                const s0l = _u64_js_1.default.rotrSL(W15h, W15l, 1) ^ _u64_js_1.default.rotrSL(W15h, W15l, 8) ^ _u64_js_1.default.shrSL(W15h, W15l, 7);
                // s1 := (w[i-2] rightrotate 19) xor (w[i-2] rightrotate 61) xor (w[i-2] rightshift 6)
                const W2h = SHA512_W_H$1[i - 2] | 0;
                const W2l = SHA512_W_L$1[i - 2] | 0;
                const s1h = _u64_js_1.default.rotrSH(W2h, W2l, 19) ^ _u64_js_1.default.rotrBH(W2h, W2l, 61) ^ _u64_js_1.default.shrSH(W2h, W2l, 6);
                const s1l = _u64_js_1.default.rotrSL(W2h, W2l, 19) ^ _u64_js_1.default.rotrBL(W2h, W2l, 61) ^ _u64_js_1.default.shrSL(W2h, W2l, 6);
                // SHA256_W[i] = s0 + s1 + SHA256_W[i - 7] + SHA256_W[i - 16];
                const SUMl = _u64_js_1.default.add4L(s0l, s1l, SHA512_W_L$1[i - 7], SHA512_W_L$1[i - 16]);
                const SUMh = _u64_js_1.default.add4H(SUMl, s0h, s1h, SHA512_W_H$1[i - 7], SHA512_W_H$1[i - 16]);
                SHA512_W_H$1[i] = SUMh | 0;
                SHA512_W_L$1[i] = SUMl | 0;
            }
            let { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
            // Compression function main loop, 80 rounds
            for (let i = 0; i < 80; i++) {
                // S1 := (e rightrotate 14) xor (e rightrotate 18) xor (e rightrotate 41)
                const sigma1h = _u64_js_1.default.rotrSH(Eh, El, 14) ^ _u64_js_1.default.rotrSH(Eh, El, 18) ^ _u64_js_1.default.rotrBH(Eh, El, 41);
                const sigma1l = _u64_js_1.default.rotrSL(Eh, El, 14) ^ _u64_js_1.default.rotrSL(Eh, El, 18) ^ _u64_js_1.default.rotrBL(Eh, El, 41);
                //const T1 = (H + sigma1 + Chi(E, F, G) + SHA256_K[i] + SHA256_W[i]) | 0;
                const CHIh = (Eh & Fh) ^ (~Eh & Gh);
                const CHIl = (El & Fl) ^ (~El & Gl);
                // T1 = H + sigma1 + Chi(E, F, G) + SHA512_K[i] + SHA512_W[i]
                // prettier-ignore
                const T1ll = _u64_js_1.default.add5L(Hl, sigma1l, CHIl, SHA512_Kl$1[i], SHA512_W_L$1[i]);
                const T1h = _u64_js_1.default.add5H(T1ll, Hh, sigma1h, CHIh, SHA512_Kh$1[i], SHA512_W_H$1[i]);
                const T1l = T1ll | 0;
                // S0 := (a rightrotate 28) xor (a rightrotate 34) xor (a rightrotate 39)
                const sigma0h = _u64_js_1.default.rotrSH(Ah, Al, 28) ^ _u64_js_1.default.rotrBH(Ah, Al, 34) ^ _u64_js_1.default.rotrBH(Ah, Al, 39);
                const sigma0l = _u64_js_1.default.rotrSL(Ah, Al, 28) ^ _u64_js_1.default.rotrBL(Ah, Al, 34) ^ _u64_js_1.default.rotrBL(Ah, Al, 39);
                const MAJh = (Ah & Bh) ^ (Ah & Ch) ^ (Bh & Ch);
                const MAJl = (Al & Bl) ^ (Al & Cl) ^ (Bl & Cl);
                Hh = Gh | 0;
                Hl = Gl | 0;
                Gh = Fh | 0;
                Gl = Fl | 0;
                Fh = Eh | 0;
                Fl = El | 0;
                ({ h: Eh, l: El } = _u64_js_1.default.add(Dh | 0, Dl | 0, T1h | 0, T1l | 0));
                Dh = Ch | 0;
                Dl = Cl | 0;
                Ch = Bh | 0;
                Cl = Bl | 0;
                Bh = Ah | 0;
                Bl = Al | 0;
                const All = _u64_js_1.default.add3L(T1l, sigma0l, MAJl);
                Ah = _u64_js_1.default.add3H(All, T1h, sigma0h, MAJh);
                Al = All | 0;
            }
            // Add the compressed chunk to the current hash value
            ({ h: Ah, l: Al } = _u64_js_1.default.add(this.Ah | 0, this.Al | 0, Ah | 0, Al | 0));
            ({ h: Bh, l: Bl } = _u64_js_1.default.add(this.Bh | 0, this.Bl | 0, Bh | 0, Bl | 0));
            ({ h: Ch, l: Cl } = _u64_js_1.default.add(this.Ch | 0, this.Cl | 0, Ch | 0, Cl | 0));
            ({ h: Dh, l: Dl } = _u64_js_1.default.add(this.Dh | 0, this.Dl | 0, Dh | 0, Dl | 0));
            ({ h: Eh, l: El } = _u64_js_1.default.add(this.Eh | 0, this.El | 0, Eh | 0, El | 0));
            ({ h: Fh, l: Fl } = _u64_js_1.default.add(this.Fh | 0, this.Fl | 0, Fh | 0, Fl | 0));
            ({ h: Gh, l: Gl } = _u64_js_1.default.add(this.Gh | 0, this.Gl | 0, Gh | 0, Gl | 0));
            ({ h: Hh, l: Hl } = _u64_js_1.default.add(this.Hh | 0, this.Hl | 0, Hh | 0, Hl | 0));
            this.set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl);
        }
        roundClean() {
            SHA512_W_H$1.fill(0);
            SHA512_W_L$1.fill(0);
        }
        destroy() {
            this.buffer.fill(0);
            this.set(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        }
    };
    sha512$1.SHA512 = SHA512$1;
    let SHA512_224$1 = class SHA512_224 extends SHA512$1 {
        constructor() {
            super();
            // h -- high 32 bits, l -- low 32 bits
            this.Ah = 0x8c3d37c8 | 0;
            this.Al = 0x19544da2 | 0;
            this.Bh = 0x73e19966 | 0;
            this.Bl = 0x89dcd4d6 | 0;
            this.Ch = 0x1dfab7ae | 0;
            this.Cl = 0x32ff9c82 | 0;
            this.Dh = 0x679dd514 | 0;
            this.Dl = 0x582f9fcf | 0;
            this.Eh = 0x0f6d2b69 | 0;
            this.El = 0x7bd44da8 | 0;
            this.Fh = 0x77e36f73 | 0;
            this.Fl = 0x04c48942 | 0;
            this.Gh = 0x3f9d85a8 | 0;
            this.Gl = 0x6a1d36c8 | 0;
            this.Hh = 0x1112e6ad | 0;
            this.Hl = 0x91d692a1 | 0;
            this.outputLen = 28;
        }
    };
    let SHA512_256$1 = class SHA512_256 extends SHA512$1 {
        constructor() {
            super();
            // h -- high 32 bits, l -- low 32 bits
            this.Ah = 0x22312194 | 0;
            this.Al = 0xfc2bf72c | 0;
            this.Bh = 0x9f555fa3 | 0;
            this.Bl = 0xc84c64c2 | 0;
            this.Ch = 0x2393b86b | 0;
            this.Cl = 0x6f53b151 | 0;
            this.Dh = 0x96387719 | 0;
            this.Dl = 0x5940eabd | 0;
            this.Eh = 0x96283ee2 | 0;
            this.El = 0xa88effe3 | 0;
            this.Fh = 0xbe5e1e25 | 0;
            this.Fl = 0x53863992 | 0;
            this.Gh = 0x2b0199fc | 0;
            this.Gl = 0x2c85b8aa | 0;
            this.Hh = 0x0eb72ddc | 0;
            this.Hl = 0x81c52ca2 | 0;
            this.outputLen = 32;
        }
    };
    let SHA384$1 = class SHA384 extends SHA512$1 {
        constructor() {
            super();
            // h -- high 32 bits, l -- low 32 bits
            this.Ah = 0xcbbb9d5d | 0;
            this.Al = 0xc1059ed8 | 0;
            this.Bh = 0x629a292a | 0;
            this.Bl = 0x367cd507 | 0;
            this.Ch = 0x9159015a | 0;
            this.Cl = 0x3070dd17 | 0;
            this.Dh = 0x152fecd8 | 0;
            this.Dl = 0xf70e5939 | 0;
            this.Eh = 0x67332667 | 0;
            this.El = 0xffc00b31 | 0;
            this.Fh = 0x8eb44a87 | 0;
            this.Fl = 0x68581511 | 0;
            this.Gh = 0xdb0c2e0d | 0;
            this.Gl = 0x64f98fa7 | 0;
            this.Hh = 0x47b5481d | 0;
            this.Hl = 0xbefa4fa4 | 0;
            this.outputLen = 48;
        }
    };
    sha512$1.sha512 = (0, utils_js_1.wrapConstructor)(() => new SHA512$1());
    sha512$1.sha512_224 = (0, utils_js_1.wrapConstructor)(() => new SHA512_224$1());
    sha512$1.sha512_256 = (0, utils_js_1.wrapConstructor)(() => new SHA512_256$1());
    sha512$1.sha384 = (0, utils_js_1.wrapConstructor)(() => new SHA384$1());

    var lib = {};

    (function (exports) {
    	/*! scure-base - MIT License (c) 2022 Paul Miller (paulmillr.com) */
    	Object.defineProperty(exports, "__esModule", { value: true });
    	exports.bytes = exports.stringToBytes = exports.str = exports.bytesToString = exports.hex = exports.utf8 = exports.bech32m = exports.bech32 = exports.base58check = exports.base58xmr = exports.base58xrp = exports.base58flickr = exports.base58 = exports.base64url = exports.base64 = exports.base32crockford = exports.base32hex = exports.base32 = exports.base16 = exports.utils = exports.assertNumber = void 0;
    	function assertNumber(n) {
    	    if (!Number.isSafeInteger(n))
    	        throw new Error(`Wrong integer: ${n}`);
    	}
    	exports.assertNumber = assertNumber;
    	function chain(...args) {
    	    const wrap = (a, b) => (c) => a(b(c));
    	    const encode = Array.from(args)
    	        .reverse()
    	        .reduce((acc, i) => (acc ? wrap(acc, i.encode) : i.encode), undefined);
    	    const decode = args.reduce((acc, i) => (acc ? wrap(acc, i.decode) : i.decode), undefined);
    	    return { encode, decode };
    	}
    	function alphabet(alphabet) {
    	    return {
    	        encode: (digits) => {
    	            if (!Array.isArray(digits) || (digits.length && typeof digits[0] !== 'number'))
    	                throw new Error('alphabet.encode input should be an array of numbers');
    	            return digits.map((i) => {
    	                assertNumber(i);
    	                if (i < 0 || i >= alphabet.length)
    	                    throw new Error(`Digit index outside alphabet: ${i} (alphabet: ${alphabet.length})`);
    	                return alphabet[i];
    	            });
    	        },
    	        decode: (input) => {
    	            if (!Array.isArray(input) || (input.length && typeof input[0] !== 'string'))
    	                throw new Error('alphabet.decode input should be array of strings');
    	            return input.map((letter) => {
    	                if (typeof letter !== 'string')
    	                    throw new Error(`alphabet.decode: not string element=${letter}`);
    	                const index = alphabet.indexOf(letter);
    	                if (index === -1)
    	                    throw new Error(`Unknown letter: "${letter}". Allowed: ${alphabet}`);
    	                return index;
    	            });
    	        },
    	    };
    	}
    	function join(separator = '') {
    	    if (typeof separator !== 'string')
    	        throw new Error('join separator should be string');
    	    return {
    	        encode: (from) => {
    	            if (!Array.isArray(from) || (from.length && typeof from[0] !== 'string'))
    	                throw new Error('join.encode input should be array of strings');
    	            for (let i of from)
    	                if (typeof i !== 'string')
    	                    throw new Error(`join.encode: non-string input=${i}`);
    	            return from.join(separator);
    	        },
    	        decode: (to) => {
    	            if (typeof to !== 'string')
    	                throw new Error('join.decode input should be string');
    	            return to.split(separator);
    	        },
    	    };
    	}
    	function padding(bits, chr = '=') {
    	    assertNumber(bits);
    	    if (typeof chr !== 'string')
    	        throw new Error('padding chr should be string');
    	    return {
    	        encode(data) {
    	            if (!Array.isArray(data) || (data.length && typeof data[0] !== 'string'))
    	                throw new Error('padding.encode input should be array of strings');
    	            for (let i of data)
    	                if (typeof i !== 'string')
    	                    throw new Error(`padding.encode: non-string input=${i}`);
    	            while ((data.length * bits) % 8)
    	                data.push(chr);
    	            return data;
    	        },
    	        decode(input) {
    	            if (!Array.isArray(input) || (input.length && typeof input[0] !== 'string'))
    	                throw new Error('padding.encode input should be array of strings');
    	            for (let i of input)
    	                if (typeof i !== 'string')
    	                    throw new Error(`padding.decode: non-string input=${i}`);
    	            let end = input.length;
    	            if ((end * bits) % 8)
    	                throw new Error('Invalid padding: string should have whole number of bytes');
    	            for (; end > 0 && input[end - 1] === chr; end--) {
    	                if (!(((end - 1) * bits) % 8))
    	                    throw new Error('Invalid padding: string has too much padding');
    	            }
    	            return input.slice(0, end);
    	        },
    	    };
    	}
    	function normalize(fn) {
    	    if (typeof fn !== 'function')
    	        throw new Error('normalize fn should be function');
    	    return { encode: (from) => from, decode: (to) => fn(to) };
    	}
    	function convertRadix(data, from, to) {
    	    if (from < 2)
    	        throw new Error(`convertRadix: wrong from=${from}, base cannot be less than 2`);
    	    if (to < 2)
    	        throw new Error(`convertRadix: wrong to=${to}, base cannot be less than 2`);
    	    if (!Array.isArray(data))
    	        throw new Error('convertRadix: data should be array');
    	    if (!data.length)
    	        return [];
    	    let pos = 0;
    	    const res = [];
    	    const digits = Array.from(data);
    	    digits.forEach((d) => {
    	        assertNumber(d);
    	        if (d < 0 || d >= from)
    	            throw new Error(`Wrong integer: ${d}`);
    	    });
    	    while (true) {
    	        let carry = 0;
    	        let done = true;
    	        for (let i = pos; i < digits.length; i++) {
    	            const digit = digits[i];
    	            const digitBase = from * carry + digit;
    	            if (!Number.isSafeInteger(digitBase) ||
    	                (from * carry) / from !== carry ||
    	                digitBase - digit !== from * carry) {
    	                throw new Error('convertRadix: carry overflow');
    	            }
    	            carry = digitBase % to;
    	            digits[i] = Math.floor(digitBase / to);
    	            if (!Number.isSafeInteger(digits[i]) || digits[i] * to + carry !== digitBase)
    	                throw new Error('convertRadix: carry overflow');
    	            if (!done)
    	                continue;
    	            else if (!digits[i])
    	                pos = i;
    	            else
    	                done = false;
    	        }
    	        res.push(carry);
    	        if (done)
    	            break;
    	    }
    	    for (let i = 0; i < data.length - 1 && data[i] === 0; i++)
    	        res.push(0);
    	    return res.reverse();
    	}
    	const gcd = (a, b) => (!b ? a : gcd(b, a % b));
    	const radix2carry = (from, to) => from + (to - gcd(from, to));
    	function convertRadix2(data, from, to, padding) {
    	    if (!Array.isArray(data))
    	        throw new Error('convertRadix2: data should be array');
    	    if (from <= 0 || from > 32)
    	        throw new Error(`convertRadix2: wrong from=${from}`);
    	    if (to <= 0 || to > 32)
    	        throw new Error(`convertRadix2: wrong to=${to}`);
    	    if (radix2carry(from, to) > 32) {
    	        throw new Error(`convertRadix2: carry overflow from=${from} to=${to} carryBits=${radix2carry(from, to)}`);
    	    }
    	    let carry = 0;
    	    let pos = 0;
    	    const mask = 2 ** to - 1;
    	    const res = [];
    	    for (const n of data) {
    	        assertNumber(n);
    	        if (n >= 2 ** from)
    	            throw new Error(`convertRadix2: invalid data word=${n} from=${from}`);
    	        carry = (carry << from) | n;
    	        if (pos + from > 32)
    	            throw new Error(`convertRadix2: carry overflow pos=${pos} from=${from}`);
    	        pos += from;
    	        for (; pos >= to; pos -= to)
    	            res.push(((carry >> (pos - to)) & mask) >>> 0);
    	        carry &= 2 ** pos - 1;
    	    }
    	    carry = (carry << (to - pos)) & mask;
    	    if (!padding && pos >= from)
    	        throw new Error('Excess padding');
    	    if (!padding && carry)
    	        throw new Error(`Non-zero padding: ${carry}`);
    	    if (padding && pos > 0)
    	        res.push(carry >>> 0);
    	    return res;
    	}
    	function radix(num) {
    	    assertNumber(num);
    	    return {
    	        encode: (bytes) => {
    	            if (!(bytes instanceof Uint8Array))
    	                throw new Error('radix.encode input should be Uint8Array');
    	            return convertRadix(Array.from(bytes), 2 ** 8, num);
    	        },
    	        decode: (digits) => {
    	            if (!Array.isArray(digits) || (digits.length && typeof digits[0] !== 'number'))
    	                throw new Error('radix.decode input should be array of strings');
    	            return Uint8Array.from(convertRadix(digits, num, 2 ** 8));
    	        },
    	    };
    	}
    	function radix2(bits, revPadding = false) {
    	    assertNumber(bits);
    	    if (bits <= 0 || bits > 32)
    	        throw new Error('radix2: bits should be in (0..32]');
    	    if (radix2carry(8, bits) > 32 || radix2carry(bits, 8) > 32)
    	        throw new Error('radix2: carry overflow');
    	    return {
    	        encode: (bytes) => {
    	            if (!(bytes instanceof Uint8Array))
    	                throw new Error('radix2.encode input should be Uint8Array');
    	            return convertRadix2(Array.from(bytes), 8, bits, !revPadding);
    	        },
    	        decode: (digits) => {
    	            if (!Array.isArray(digits) || (digits.length && typeof digits[0] !== 'number'))
    	                throw new Error('radix2.decode input should be array of strings');
    	            return Uint8Array.from(convertRadix2(digits, bits, 8, revPadding));
    	        },
    	    };
    	}
    	function unsafeWrapper(fn) {
    	    if (typeof fn !== 'function')
    	        throw new Error('unsafeWrapper fn should be function');
    	    return function (...args) {
    	        try {
    	            return fn.apply(null, args);
    	        }
    	        catch (e) { }
    	    };
    	}
    	function checksum(len, fn) {
    	    assertNumber(len);
    	    if (typeof fn !== 'function')
    	        throw new Error('checksum fn should be function');
    	    return {
    	        encode(data) {
    	            if (!(data instanceof Uint8Array))
    	                throw new Error('checksum.encode: input should be Uint8Array');
    	            const checksum = fn(data).slice(0, len);
    	            const res = new Uint8Array(data.length + len);
    	            res.set(data);
    	            res.set(checksum, data.length);
    	            return res;
    	        },
    	        decode(data) {
    	            if (!(data instanceof Uint8Array))
    	                throw new Error('checksum.decode: input should be Uint8Array');
    	            const payload = data.slice(0, -len);
    	            const newChecksum = fn(payload).slice(0, len);
    	            const oldChecksum = data.slice(-len);
    	            for (let i = 0; i < len; i++)
    	                if (newChecksum[i] !== oldChecksum[i])
    	                    throw new Error('Invalid checksum');
    	            return payload;
    	        },
    	    };
    	}
    	exports.utils = { alphabet, chain, checksum, radix, radix2, join, padding };
    	exports.base16 = chain(radix2(4), alphabet('0123456789ABCDEF'), join(''));
    	exports.base32 = chain(radix2(5), alphabet('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'), padding(5), join(''));
    	exports.base32hex = chain(radix2(5), alphabet('0123456789ABCDEFGHIJKLMNOPQRSTUV'), padding(5), join(''));
    	exports.base32crockford = chain(radix2(5), alphabet('0123456789ABCDEFGHJKMNPQRSTVWXYZ'), join(''), normalize((s) => s.toUpperCase().replace(/O/g, '0').replace(/[IL]/g, '1')));
    	exports.base64 = chain(radix2(6), alphabet('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'), padding(6), join(''));
    	exports.base64url = chain(radix2(6), alphabet('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'), padding(6), join(''));
    	const genBase58 = (abc) => chain(radix(58), alphabet(abc), join(''));
    	exports.base58 = genBase58('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz');
    	exports.base58flickr = genBase58('123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ');
    	exports.base58xrp = genBase58('rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz');
    	const XMR_BLOCK_LEN = [0, 2, 3, 5, 6, 7, 9, 10, 11];
    	exports.base58xmr = {
    	    encode(data) {
    	        let res = '';
    	        for (let i = 0; i < data.length; i += 8) {
    	            const block = data.subarray(i, i + 8);
    	            res += exports.base58.encode(block).padStart(XMR_BLOCK_LEN[block.length], '1');
    	        }
    	        return res;
    	    },
    	    decode(str) {
    	        let res = [];
    	        for (let i = 0; i < str.length; i += 11) {
    	            const slice = str.slice(i, i + 11);
    	            const blockLen = XMR_BLOCK_LEN.indexOf(slice.length);
    	            const block = exports.base58.decode(slice);
    	            for (let j = 0; j < block.length - blockLen; j++) {
    	                if (block[j] !== 0)
    	                    throw new Error('base58xmr: wrong padding');
    	            }
    	            res = res.concat(Array.from(block.slice(block.length - blockLen)));
    	        }
    	        return Uint8Array.from(res);
    	    },
    	};
    	const base58check = (sha256) => chain(checksum(4, (data) => sha256(sha256(data))), exports.base58);
    	exports.base58check = base58check;
    	const BECH_ALPHABET = chain(alphabet('qpzry9x8gf2tvdw0s3jn54khce6mua7l'), join(''));
    	const POLYMOD_GENERATORS = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    	function bech32Polymod(pre) {
    	    const b = pre >> 25;
    	    let chk = (pre & 0x1ffffff) << 5;
    	    for (let i = 0; i < POLYMOD_GENERATORS.length; i++) {
    	        if (((b >> i) & 1) === 1)
    	            chk ^= POLYMOD_GENERATORS[i];
    	    }
    	    return chk;
    	}
    	function bechChecksum(prefix, words, encodingConst = 1) {
    	    const len = prefix.length;
    	    let chk = 1;
    	    for (let i = 0; i < len; i++) {
    	        const c = prefix.charCodeAt(i);
    	        if (c < 33 || c > 126)
    	            throw new Error(`Invalid prefix (${prefix})`);
    	        chk = bech32Polymod(chk) ^ (c >> 5);
    	    }
    	    chk = bech32Polymod(chk);
    	    for (let i = 0; i < len; i++)
    	        chk = bech32Polymod(chk) ^ (prefix.charCodeAt(i) & 0x1f);
    	    for (let v of words)
    	        chk = bech32Polymod(chk) ^ v;
    	    for (let i = 0; i < 6; i++)
    	        chk = bech32Polymod(chk);
    	    chk ^= encodingConst;
    	    return BECH_ALPHABET.encode(convertRadix2([chk % 2 ** 30], 30, 5, false));
    	}
    	function genBech32(encoding) {
    	    const ENCODING_CONST = encoding === 'bech32' ? 1 : 0x2bc830a3;
    	    const _words = radix2(5);
    	    const fromWords = _words.decode;
    	    const toWords = _words.encode;
    	    const fromWordsUnsafe = unsafeWrapper(fromWords);
    	    function encode(prefix, words, limit = 90) {
    	        if (typeof prefix !== 'string')
    	            throw new Error(`bech32.encode prefix should be string, not ${typeof prefix}`);
    	        if (!Array.isArray(words) || (words.length && typeof words[0] !== 'number'))
    	            throw new Error(`bech32.encode words should be array of numbers, not ${typeof words}`);
    	        const actualLength = prefix.length + 7 + words.length;
    	        if (limit !== false && actualLength > limit)
    	            throw new TypeError(`Length ${actualLength} exceeds limit ${limit}`);
    	        prefix = prefix.toLowerCase();
    	        return `${prefix}1${BECH_ALPHABET.encode(words)}${bechChecksum(prefix, words, ENCODING_CONST)}`;
    	    }
    	    function decode(str, limit = 90) {
    	        if (typeof str !== 'string')
    	            throw new Error(`bech32.decode input should be string, not ${typeof str}`);
    	        if (str.length < 8 || (limit !== false && str.length > limit))
    	            throw new TypeError(`Wrong string length: ${str.length} (${str}). Expected (8..${limit})`);
    	        const lowered = str.toLowerCase();
    	        if (str !== lowered && str !== str.toUpperCase())
    	            throw new Error(`String must be lowercase or uppercase`);
    	        str = lowered;
    	        const sepIndex = str.lastIndexOf('1');
    	        if (sepIndex === 0 || sepIndex === -1)
    	            throw new Error(`Letter "1" must be present between prefix and data only`);
    	        const prefix = str.slice(0, sepIndex);
    	        const _words = str.slice(sepIndex + 1);
    	        if (_words.length < 6)
    	            throw new Error('Data must be at least 6 characters long');
    	        const words = BECH_ALPHABET.decode(_words).slice(0, -6);
    	        const sum = bechChecksum(prefix, words, ENCODING_CONST);
    	        if (!_words.endsWith(sum))
    	            throw new Error(`Invalid checksum in ${str}: expected "${sum}"`);
    	        return { prefix, words };
    	    }
    	    const decodeUnsafe = unsafeWrapper(decode);
    	    function decodeToBytes(str) {
    	        const { prefix, words } = decode(str, false);
    	        return { prefix, words, bytes: fromWords(words) };
    	    }
    	    return { encode, decode, decodeToBytes, decodeUnsafe, fromWords, fromWordsUnsafe, toWords };
    	}
    	exports.bech32 = genBech32('bech32');
    	exports.bech32m = genBech32('bech32m');
    	exports.utf8 = {
    	    encode: (data) => new TextDecoder().decode(data),
    	    decode: (str) => new TextEncoder().encode(str),
    	};
    	exports.hex = chain(radix2(4), alphabet('0123456789abcdef'), join(''), normalize((s) => {
    	    if (typeof s !== 'string' || s.length % 2)
    	        throw new TypeError(`hex.decode: expected string, got ${typeof s} with length ${s.length}`);
    	    return s.toLowerCase();
    	}));
    	const CODERS = {
    	    utf8: exports.utf8, hex: exports.hex, base16: exports.base16, base32: exports.base32, base64: exports.base64, base64url: exports.base64url, base58: exports.base58, base58xmr: exports.base58xmr
    	};
    	const coderTypeError = `Invalid encoding type. Available types: ${Object.keys(CODERS).join(', ')}`;
    	const bytesToString = (type, bytes) => {
    	    if (typeof type !== 'string' || !CODERS.hasOwnProperty(type))
    	        throw new TypeError(coderTypeError);
    	    if (!(bytes instanceof Uint8Array))
    	        throw new TypeError('bytesToString() expects Uint8Array');
    	    return CODERS[type].encode(bytes);
    	};
    	exports.bytesToString = bytesToString;
    	exports.str = exports.bytesToString;
    	const stringToBytes = (type, str) => {
    	    if (!CODERS.hasOwnProperty(type))
    	        throw new TypeError(coderTypeError);
    	    if (typeof str !== 'string')
    	        throw new TypeError('stringToBytes() expects string');
    	    return CODERS[type].decode(str);
    	};
    	exports.stringToBytes = stringToBytes;
    	exports.bytes = exports.stringToBytes; 
    } (lib));

    Object.defineProperty(bip39, "__esModule", { value: true });
    var mnemonicToSeedSync_1 = bip39.mnemonicToSeedSync = bip39.mnemonicToSeed = validateMnemonic_1 = bip39.validateMnemonic = bip39.entropyToMnemonic = bip39.mnemonicToEntropy = generateMnemonic_1 = bip39.generateMnemonic = void 0;
    /*! scure-bip39 - MIT License (c) 2022 Patricio Palladino, Paul Miller (paulmillr.com) */
    const _assert_1 = _assert;
    const pbkdf2_1 = pbkdf2$1;
    const sha256_1 = sha256$2;
    const sha512_1 = sha512$1;
    const utils_1 = utils;
    const base_1 = lib;
    // Japanese wordlist
    const isJapanese = (wordlist) => wordlist[0] === '\u3042\u3044\u3053\u304f\u3057\u3093';
    // Normalization replaces equivalent sequences of characters
    // so that any two texts that are equivalent will be reduced
    // to the same sequence of code points, called the normal form of the original text.
    function nfkd(str) {
        if (typeof str !== 'string')
            throw new TypeError(`Invalid mnemonic type: ${typeof str}`);
        return str.normalize('NFKD');
    }
    function normalize(str) {
        const norm = nfkd(str);
        const words = norm.split(' ');
        if (![12, 15, 18, 21, 24].includes(words.length))
            throw new Error('Invalid mnemonic');
        return { nfkd: norm, words };
    }
    function assertEntropy(entropy) {
        _assert_1.default.bytes(entropy, 16, 20, 24, 28, 32);
    }
    /**
     * Generate x random words. Uses Cryptographically-Secure Random Number Generator.
     * @param wordlist imported wordlist for specific language
     * @param strength mnemonic strength 128-256 bits
     * @example
     * generateMnemonic(wordlist, 128)
     * // 'legal winner thank year wave sausage worth useful legal winner thank yellow'
     */
    function generateMnemonic(wordlist, strength = 128) {
        _assert_1.default.number(strength);
        if (strength % 32 !== 0 || strength > 256)
            throw new TypeError('Invalid entropy');
        return entropyToMnemonic((0, utils_1.randomBytes)(strength / 8), wordlist);
    }
    var generateMnemonic_1 = bip39.generateMnemonic = generateMnemonic;
    const calcChecksum = (entropy) => {
        // Checksum is ent.length/4 bits long
        const bitsLeft = 8 - entropy.length / 4;
        // Zero rightmost "bitsLeft" bits in byte
        // For example: bitsLeft=4 val=10111101 -> 10110000
        return new Uint8Array([((0, sha256_1.sha256)(entropy)[0] >> bitsLeft) << bitsLeft]);
    };
    function getCoder(wordlist) {
        if (!Array.isArray(wordlist) || wordlist.length !== 2048 || typeof wordlist[0] !== 'string')
            throw new Error('Worlist: expected array of 2048 strings');
        wordlist.forEach((i) => {
            if (typeof i !== 'string')
                throw new Error(`Wordlist: non-string element: ${i}`);
        });
        return base_1.utils.chain(base_1.utils.checksum(1, calcChecksum), base_1.utils.radix2(11, true), base_1.utils.alphabet(wordlist));
    }
    /**
     * Reversible: Converts mnemonic string to raw entropy in form of byte array.
     * @param mnemonic 12-24 words
     * @param wordlist imported wordlist for specific language
     * @example
     * const mnem = 'legal winner thank year wave sausage worth useful legal winner thank yellow';
     * mnemonicToEntropy(mnem, wordlist)
     * // Produces
     * new Uint8Array([
     *   0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
     *   0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f
     * ])
     */
    function mnemonicToEntropy(mnemonic, wordlist) {
        const { words } = normalize(mnemonic);
        const entropy = getCoder(wordlist).decode(words);
        assertEntropy(entropy);
        return entropy;
    }
    bip39.mnemonicToEntropy = mnemonicToEntropy;
    /**
     * Reversible: Converts raw entropy in form of byte array to mnemonic string.
     * @param entropy byte array
     * @param wordlist imported wordlist for specific language
     * @returns 12-24 words
     * @example
     * const ent = new Uint8Array([
     *   0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
     *   0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f
     * ]);
     * entropyToMnemonic(ent, wordlist);
     * // 'legal winner thank year wave sausage worth useful legal winner thank yellow'
     */
    function entropyToMnemonic(entropy, wordlist) {
        assertEntropy(entropy);
        const words = getCoder(wordlist).encode(entropy);
        return words.join(isJapanese(wordlist) ? '\u3000' : ' ');
    }
    bip39.entropyToMnemonic = entropyToMnemonic;
    /**
     * Validates mnemonic for being 12-24 words contained in `wordlist`.
     */
    function validateMnemonic(mnemonic, wordlist) {
        try {
            mnemonicToEntropy(mnemonic, wordlist);
        }
        catch (e) {
            return false;
        }
        return true;
    }
    var validateMnemonic_1 = bip39.validateMnemonic = validateMnemonic;
    const salt = (passphrase) => nfkd(`mnemonic${passphrase}`);
    /**
     * Irreversible: Uses KDF to derive 64 bytes of key data from mnemonic + optional password.
     * @param mnemonic 12-24 words
     * @param passphrase string that will additionally protect the key
     * @returns 64 bytes of key data
     * @example
     * const mnem = 'legal winner thank year wave sausage worth useful legal winner thank yellow';
     * await mnemonicToSeed(mnem, 'password');
     * // new Uint8Array([...64 bytes])
     */
    function mnemonicToSeed(mnemonic, passphrase = '') {
        return (0, pbkdf2_1.pbkdf2Async)(sha512_1.sha512, normalize(mnemonic).nfkd, salt(passphrase), { c: 2048, dkLen: 64 });
    }
    bip39.mnemonicToSeed = mnemonicToSeed;
    /**
     * Irreversible: Uses KDF to derive 64 bytes of key data from mnemonic + optional password.
     * @param mnemonic 12-24 words
     * @param passphrase string that will additionally protect the key
     * @returns 64 bytes of key data
     * @example
     * const mnem = 'legal winner thank year wave sausage worth useful legal winner thank yellow';
     * mnemonicToSeedSync(mnem, 'password');
     * // new Uint8Array([...64 bytes])
     */
    function mnemonicToSeedSync(mnemonic, passphrase = '') {
        return (0, pbkdf2_1.pbkdf2)(sha512_1.sha512, normalize(mnemonic).nfkd, salt(passphrase), { c: 2048, dkLen: 64 });
    }
    mnemonicToSeedSync_1 = bip39.mnemonicToSeedSync = mnemonicToSeedSync;

    function number$1(n) {
        if (!Number.isSafeInteger(n) || n < 0)
            throw new Error(`Wrong positive integer: ${n}`);
    }
    function bool$1(b) {
        if (typeof b !== 'boolean')
            throw new Error(`Expected boolean, not ${b}`);
    }
    function bytes$1(b, ...lengths) {
        if (!(b instanceof Uint8Array))
            throw new TypeError('Expected Uint8Array');
        if (lengths.length > 0 && !lengths.includes(b.length))
            throw new TypeError(`Expected Uint8Array of length ${lengths}, not of length=${b.length}`);
    }
    function hash$1(hash) {
        if (typeof hash !== 'function' || typeof hash.create !== 'function')
            throw new Error('Hash should be wrapped by utils.wrapConstructor');
        number$1(hash.outputLen);
        number$1(hash.blockLen);
    }
    function exists$1(instance, checkFinished = true) {
        if (instance.destroyed)
            throw new Error('Hash instance has been destroyed');
        if (checkFinished && instance.finished)
            throw new Error('Hash#digest() has already been called');
    }
    function output$1(out, instance) {
        bytes$1(out);
        const min = instance.outputLen;
        if (out.length < min) {
            throw new Error(`digestInto() expects output buffer of length at least ${min}`);
        }
    }
    const assert$2 = {
        number: number$1,
        bool: bool$1,
        bytes: bytes$1,
        hash: hash$1,
        exists: exists$1,
        output: output$1,
    };

    /*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) */
    // The import here is via the package name. This is to ensure
    // that exports mapping/resolution does fall into place.
    // Cast array to view
    const createView$1 = (arr) => new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
    // The rotate right (circular right shift) operation for uint32
    const rotr$1 = (word, shift) => (word << (32 - shift)) | (word >>> shift);
    const isLE$1 = new Uint8Array(new Uint32Array([0x11223344]).buffer)[0] === 0x44;
    // There is almost no big endian hardware, but js typed arrays uses platform specific endianness.
    // So, just to be sure not to corrupt anything.
    if (!isLE$1)
        throw new Error('Non little-endian hardware is not supported');
    const hexes$1 = Array.from({ length: 256 }, (v, i) => i.toString(16).padStart(2, '0'));
    /**
     * @example bytesToHex(Uint8Array.from([0xde, 0xad, 0xbe, 0xef]))
     */
    function bytesToHex$1(uint8a) {
        // pre-caching improves the speed 6x
        if (!(uint8a instanceof Uint8Array))
            throw new Error('Uint8Array expected');
        let hex = '';
        for (let i = 0; i < uint8a.length; i++) {
            hex += hexes$1[uint8a[i]];
        }
        return hex;
    }
    /**
     * @example hexToBytes('deadbeef')
     */
    function hexToBytes(hex) {
        if (typeof hex !== 'string') {
            throw new TypeError('hexToBytes: expected string, got ' + typeof hex);
        }
        if (hex.length % 2)
            throw new Error('hexToBytes: received invalid unpadded hex');
        const array = new Uint8Array(hex.length / 2);
        for (let i = 0; i < array.length; i++) {
            const j = i * 2;
            const hexByte = hex.slice(j, j + 2);
            const byte = Number.parseInt(hexByte, 16);
            if (Number.isNaN(byte) || byte < 0)
                throw new Error('Invalid byte sequence');
            array[i] = byte;
        }
        return array;
    }
    function utf8ToBytes$1(str) {
        if (typeof str !== 'string') {
            throw new TypeError(`utf8ToBytes expected string, got ${typeof str}`);
        }
        return new TextEncoder().encode(str);
    }
    function toBytes$1(data) {
        if (typeof data === 'string')
            data = utf8ToBytes$1(data);
        if (!(data instanceof Uint8Array))
            throw new TypeError(`Expected input type is Uint8Array (got ${typeof data})`);
        return data;
    }
    /**
     * Concats Uint8Array-s into one; like `Buffer.concat([buf1, buf2])`
     * @example concatBytes(buf1, buf2)
     */
    function concatBytes(...arrays) {
        if (!arrays.every((a) => a instanceof Uint8Array))
            throw new Error('Uint8Array list expected');
        if (arrays.length === 1)
            return arrays[0];
        const length = arrays.reduce((a, arr) => a + arr.length, 0);
        const result = new Uint8Array(length);
        for (let i = 0, pad = 0; i < arrays.length; i++) {
            const arr = arrays[i];
            result.set(arr, pad);
            pad += arr.length;
        }
        return result;
    }
    // For runtime check if class implements interface
    let Hash$1 = class Hash {
        // Safe version that clones internal state
        clone() {
            return this._cloneInto();
        }
    };
    function wrapConstructor$1(hashConstructor) {
        const hashC = (message) => hashConstructor().update(toBytes$1(message)).digest();
        const tmp = hashConstructor();
        hashC.outputLen = tmp.outputLen;
        hashC.blockLen = tmp.blockLen;
        hashC.create = () => hashConstructor();
        return hashC;
    }

    // HMAC (RFC 2104)
    let HMAC$1 = class HMAC extends Hash$1 {
        constructor(hash, _key) {
            super();
            this.finished = false;
            this.destroyed = false;
            assert$2.hash(hash);
            const key = toBytes$1(_key);
            this.iHash = hash.create();
            if (typeof this.iHash.update !== 'function')
                throw new TypeError('Expected instance of class which extends utils.Hash');
            this.blockLen = this.iHash.blockLen;
            this.outputLen = this.iHash.outputLen;
            const blockLen = this.blockLen;
            const pad = new Uint8Array(blockLen);
            // blockLen can be bigger than outputLen
            pad.set(key.length > blockLen ? hash.create().update(key).digest() : key);
            for (let i = 0; i < pad.length; i++)
                pad[i] ^= 0x36;
            this.iHash.update(pad);
            // By doing update (processing of first block) of outer hash here we can re-use it between multiple calls via clone
            this.oHash = hash.create();
            // Undo internal XOR && apply outer XOR
            for (let i = 0; i < pad.length; i++)
                pad[i] ^= 0x36 ^ 0x5c;
            this.oHash.update(pad);
            pad.fill(0);
        }
        update(buf) {
            assert$2.exists(this);
            this.iHash.update(buf);
            return this;
        }
        digestInto(out) {
            assert$2.exists(this);
            assert$2.bytes(out, this.outputLen);
            this.finished = true;
            this.iHash.digestInto(out);
            this.oHash.update(out);
            this.oHash.digestInto(out);
            this.destroy();
        }
        digest() {
            const out = new Uint8Array(this.oHash.outputLen);
            this.digestInto(out);
            return out;
        }
        _cloneInto(to) {
            // Create new instance without calling constructor since key already in state and we don't know it.
            to || (to = Object.create(Object.getPrototypeOf(this), {}));
            const { oHash, iHash, finished, destroyed, blockLen, outputLen } = this;
            to = to;
            to.finished = finished;
            to.destroyed = destroyed;
            to.blockLen = blockLen;
            to.outputLen = outputLen;
            to.oHash = oHash._cloneInto(to.oHash);
            to.iHash = iHash._cloneInto(to.iHash);
            return to;
        }
        destroy() {
            this.destroyed = true;
            this.oHash.destroy();
            this.iHash.destroy();
        }
    };
    /**
     * HMAC: RFC2104 message authentication code.
     * @param hash - function that would be used e.g. sha256
     * @param key - message key
     * @param message - message data
     */
    const hmac$1 = (hash, key, message) => new HMAC$1(hash, key).update(message).digest();
    hmac$1.create = (hash, key) => new HMAC$1(hash, key);

    // Polyfill for Safari 14
    function setBigUint64$1(view, byteOffset, value, isLE) {
        if (typeof view.setBigUint64 === 'function')
            return view.setBigUint64(byteOffset, value, isLE);
        const _32n = BigInt(32);
        const _u32_max = BigInt(0xffffffff);
        const wh = Number((value >> _32n) & _u32_max);
        const wl = Number(value & _u32_max);
        const h = isLE ? 4 : 0;
        const l = isLE ? 0 : 4;
        view.setUint32(byteOffset + h, wh, isLE);
        view.setUint32(byteOffset + l, wl, isLE);
    }
    // Base SHA2 class (RFC 6234)
    let SHA2$1 = class SHA2 extends Hash$1 {
        constructor(blockLen, outputLen, padOffset, isLE) {
            super();
            this.blockLen = blockLen;
            this.outputLen = outputLen;
            this.padOffset = padOffset;
            this.isLE = isLE;
            this.finished = false;
            this.length = 0;
            this.pos = 0;
            this.destroyed = false;
            this.buffer = new Uint8Array(blockLen);
            this.view = createView$1(this.buffer);
        }
        update(data) {
            assert$2.exists(this);
            const { view, buffer, blockLen } = this;
            data = toBytes$1(data);
            const len = data.length;
            for (let pos = 0; pos < len;) {
                const take = Math.min(blockLen - this.pos, len - pos);
                // Fast path: we have at least one block in input, cast it to view and process
                if (take === blockLen) {
                    const dataView = createView$1(data);
                    for (; blockLen <= len - pos; pos += blockLen)
                        this.process(dataView, pos);
                    continue;
                }
                buffer.set(data.subarray(pos, pos + take), this.pos);
                this.pos += take;
                pos += take;
                if (this.pos === blockLen) {
                    this.process(view, 0);
                    this.pos = 0;
                }
            }
            this.length += data.length;
            this.roundClean();
            return this;
        }
        digestInto(out) {
            assert$2.exists(this);
            assert$2.output(out, this);
            this.finished = true;
            // Padding
            // We can avoid allocation of buffer for padding completely if it
            // was previously not allocated here. But it won't change performance.
            const { buffer, view, blockLen, isLE } = this;
            let { pos } = this;
            // append the bit '1' to the message
            buffer[pos++] = 0b10000000;
            this.buffer.subarray(pos).fill(0);
            // we have less than padOffset left in buffer, so we cannot put length in current block, need process it and pad again
            if (this.padOffset > blockLen - pos) {
                this.process(view, 0);
                pos = 0;
            }
            // Pad until full block byte with zeros
            for (let i = pos; i < blockLen; i++)
                buffer[i] = 0;
            // Note: sha512 requires length to be 128bit integer, but length in JS will overflow before that
            // You need to write around 2 exabytes (u64_max / 8 / (1024**6)) for this to happen.
            // So we just write lowest 64 bits of that value.
            setBigUint64$1(view, blockLen - 8, BigInt(this.length * 8), isLE);
            this.process(view, 0);
            const oview = createView$1(out);
            const len = this.outputLen;
            // NOTE: we do division by 4 later, which should be fused in single op with modulo by JIT
            if (len % 4)
                throw new Error('_sha2: outputLen should be aligned to 32bit');
            const outLen = len / 4;
            const state = this.get();
            if (outLen > state.length)
                throw new Error('_sha2: outputLen bigger than state');
            for (let i = 0; i < outLen; i++)
                oview.setUint32(4 * i, state[i], isLE);
        }
        digest() {
            const { buffer, outputLen } = this;
            this.digestInto(buffer);
            const res = buffer.slice(0, outputLen);
            this.destroy();
            return res;
        }
        _cloneInto(to) {
            to || (to = new this.constructor());
            to.set(...this.get());
            const { blockLen, buffer, length, finished, destroyed, pos } = this;
            to.length = length;
            to.pos = pos;
            to.finished = finished;
            to.destroyed = destroyed;
            if (length % blockLen)
                to.buffer.set(buffer);
            return to;
        }
    };

    // https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
    // https://homes.esat.kuleuven.be/~bosselae/ripemd160/pdf/AB-9601/AB-9601.pdf
    const Rho = new Uint8Array([7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8]);
    const Id = Uint8Array.from({ length: 16 }, (_, i) => i);
    const Pi = Id.map((i) => (9 * i + 5) % 16);
    let idxL = [Id];
    let idxR = [Pi];
    for (let i = 0; i < 4; i++)
        for (let j of [idxL, idxR])
            j.push(j[i].map((k) => Rho[k]));
    const shifts = [
        [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8],
        [12, 13, 11, 15, 6, 9, 9, 7, 12, 15, 11, 13, 7, 8, 7, 7],
        [13, 15, 14, 11, 7, 7, 6, 8, 13, 14, 13, 12, 5, 5, 6, 9],
        [14, 11, 12, 14, 8, 6, 5, 5, 15, 12, 15, 14, 9, 9, 8, 6],
        [15, 12, 13, 13, 9, 5, 8, 6, 14, 11, 12, 11, 8, 6, 5, 5],
    ].map((i) => new Uint8Array(i));
    const shiftsL = idxL.map((idx, i) => idx.map((j) => shifts[i][j]));
    const shiftsR = idxR.map((idx, i) => idx.map((j) => shifts[i][j]));
    const Kl = new Uint32Array([0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e]);
    const Kr = new Uint32Array([0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000]);
    // The rotate left (circular left shift) operation for uint32
    const rotl = (word, shift) => (word << shift) | (word >>> (32 - shift));
    // It's called f() in spec.
    function f(group, x, y, z) {
        if (group === 0)
            return x ^ y ^ z;
        else if (group === 1)
            return (x & y) | (~x & z);
        else if (group === 2)
            return (x | ~y) ^ z;
        else if (group === 3)
            return (x & z) | (y & ~z);
        else
            return x ^ (y | ~z);
    }
    // Temporary buffer, not used to store anything between runs
    const BUF = new Uint32Array(16);
    class RIPEMD160 extends SHA2$1 {
        constructor() {
            super(64, 20, 8, true);
            this.h0 = 0x67452301 | 0;
            this.h1 = 0xefcdab89 | 0;
            this.h2 = 0x98badcfe | 0;
            this.h3 = 0x10325476 | 0;
            this.h4 = 0xc3d2e1f0 | 0;
        }
        get() {
            const { h0, h1, h2, h3, h4 } = this;
            return [h0, h1, h2, h3, h4];
        }
        set(h0, h1, h2, h3, h4) {
            this.h0 = h0 | 0;
            this.h1 = h1 | 0;
            this.h2 = h2 | 0;
            this.h3 = h3 | 0;
            this.h4 = h4 | 0;
        }
        process(view, offset) {
            for (let i = 0; i < 16; i++, offset += 4)
                BUF[i] = view.getUint32(offset, true);
            // prettier-ignore
            let al = this.h0 | 0, ar = al, bl = this.h1 | 0, br = bl, cl = this.h2 | 0, cr = cl, dl = this.h3 | 0, dr = dl, el = this.h4 | 0, er = el;
            // Instead of iterating 0 to 80, we split it into 5 groups
            // And use the groups in constants, functions, etc. Much simpler
            for (let group = 0; group < 5; group++) {
                const rGroup = 4 - group;
                const hbl = Kl[group], hbr = Kr[group]; // prettier-ignore
                const rl = idxL[group], rr = idxR[group]; // prettier-ignore
                const sl = shiftsL[group], sr = shiftsR[group]; // prettier-ignore
                for (let i = 0; i < 16; i++) {
                    const tl = (rotl(al + f(group, bl, cl, dl) + BUF[rl[i]] + hbl, sl[i]) + el) | 0;
                    al = el, el = dl, dl = rotl(cl, 10) | 0, cl = bl, bl = tl; // prettier-ignore
                }
                // 2 loops are 10% faster
                for (let i = 0; i < 16; i++) {
                    const tr = (rotl(ar + f(rGroup, br, cr, dr) + BUF[rr[i]] + hbr, sr[i]) + er) | 0;
                    ar = er, er = dr, dr = rotl(cr, 10) | 0, cr = br, br = tr; // prettier-ignore
                }
            }
            // Add the compressed chunk to the current hash value
            this.set((this.h1 + cl + dr) | 0, (this.h2 + dl + er) | 0, (this.h3 + el + ar) | 0, (this.h4 + al + br) | 0, (this.h0 + bl + cr) | 0);
        }
        roundClean() {
            BUF.fill(0);
        }
        destroy() {
            this.destroyed = true;
            this.buffer.fill(0);
            this.set(0, 0, 0, 0, 0);
        }
    }
    /**
     * RIPEMD-160 - a hash function from 1990s.
     * @param message - msg that would be hashed
     */
    const ripemd160 = wrapConstructor$1(() => new RIPEMD160());

    // Choice: a ? b : c
    const Chi$1 = (a, b, c) => (a & b) ^ (~a & c);
    // Majority function, true if any two inpust is true
    const Maj$1 = (a, b, c) => (a & b) ^ (a & c) ^ (b & c);
    // Round constants:
    // first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311)
    // prettier-ignore
    const SHA256_K$1 = new Uint32Array([
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]);
    // Initial state (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
    // prettier-ignore
    const IV$1 = new Uint32Array([
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]);
    // Temporary buffer, not used to store anything between runs
    // Named this way because it matches specification.
    const SHA256_W$1 = new Uint32Array(64);
    let SHA256$1 = class SHA256 extends SHA2$1 {
        constructor() {
            super(64, 32, 8, false);
            // We cannot use array here since array allows indexing by variable
            // which means optimizer/compiler cannot use registers.
            this.A = IV$1[0] | 0;
            this.B = IV$1[1] | 0;
            this.C = IV$1[2] | 0;
            this.D = IV$1[3] | 0;
            this.E = IV$1[4] | 0;
            this.F = IV$1[5] | 0;
            this.G = IV$1[6] | 0;
            this.H = IV$1[7] | 0;
        }
        get() {
            const { A, B, C, D, E, F, G, H } = this;
            return [A, B, C, D, E, F, G, H];
        }
        // prettier-ignore
        set(A, B, C, D, E, F, G, H) {
            this.A = A | 0;
            this.B = B | 0;
            this.C = C | 0;
            this.D = D | 0;
            this.E = E | 0;
            this.F = F | 0;
            this.G = G | 0;
            this.H = H | 0;
        }
        process(view, offset) {
            // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array
            for (let i = 0; i < 16; i++, offset += 4)
                SHA256_W$1[i] = view.getUint32(offset, false);
            for (let i = 16; i < 64; i++) {
                const W15 = SHA256_W$1[i - 15];
                const W2 = SHA256_W$1[i - 2];
                const s0 = rotr$1(W15, 7) ^ rotr$1(W15, 18) ^ (W15 >>> 3);
                const s1 = rotr$1(W2, 17) ^ rotr$1(W2, 19) ^ (W2 >>> 10);
                SHA256_W$1[i] = (s1 + SHA256_W$1[i - 7] + s0 + SHA256_W$1[i - 16]) | 0;
            }
            // Compression function main loop, 64 rounds
            let { A, B, C, D, E, F, G, H } = this;
            for (let i = 0; i < 64; i++) {
                const sigma1 = rotr$1(E, 6) ^ rotr$1(E, 11) ^ rotr$1(E, 25);
                const T1 = (H + sigma1 + Chi$1(E, F, G) + SHA256_K$1[i] + SHA256_W$1[i]) | 0;
                const sigma0 = rotr$1(A, 2) ^ rotr$1(A, 13) ^ rotr$1(A, 22);
                const T2 = (sigma0 + Maj$1(A, B, C)) | 0;
                H = G;
                G = F;
                F = E;
                E = (D + T1) | 0;
                D = C;
                C = B;
                B = A;
                A = (T1 + T2) | 0;
            }
            // Add the compressed chunk to the current hash value
            A = (A + this.A) | 0;
            B = (B + this.B) | 0;
            C = (C + this.C) | 0;
            D = (D + this.D) | 0;
            E = (E + this.E) | 0;
            F = (F + this.F) | 0;
            G = (G + this.G) | 0;
            H = (H + this.H) | 0;
            this.set(A, B, C, D, E, F, G, H);
        }
        roundClean() {
            SHA256_W$1.fill(0);
        }
        destroy() {
            this.set(0, 0, 0, 0, 0, 0, 0, 0);
            this.buffer.fill(0);
        }
    };
    // Constants from https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
    let SHA224$1 = class SHA224 extends SHA256$1 {
        constructor() {
            super();
            this.A = 0xc1059ed8 | 0;
            this.B = 0x367cd507 | 0;
            this.C = 0x3070dd17 | 0;
            this.D = 0xf70e5939 | 0;
            this.E = 0xffc00b31 | 0;
            this.F = 0x68581511 | 0;
            this.G = 0x64f98fa7 | 0;
            this.H = 0xbefa4fa4 | 0;
            this.outputLen = 28;
        }
    };
    /**
     * SHA2-256 hash function
     * @param message - data that would be hashed
     */
    const sha256$1 = wrapConstructor$1(() => new SHA256$1());
    wrapConstructor$1(() => new SHA224$1());

    const U32_MASK64 = BigInt(2 ** 32 - 1);
    const _32n = BigInt(32);
    // We are not using BigUint64Array, because they are extremely slow as per 2022
    function fromBig(n, le = false) {
        if (le)
            return { h: Number(n & U32_MASK64), l: Number((n >> _32n) & U32_MASK64) };
        return { h: Number((n >> _32n) & U32_MASK64) | 0, l: Number(n & U32_MASK64) | 0 };
    }
    function split(lst, le = false) {
        let Ah = new Uint32Array(lst.length);
        let Al = new Uint32Array(lst.length);
        for (let i = 0; i < lst.length; i++) {
            const { h, l } = fromBig(lst[i], le);
            [Ah[i], Al[i]] = [h, l];
        }
        return [Ah, Al];
    }
    const toBig = (h, l) => (BigInt(h >>> 0) << _32n) | BigInt(l >>> 0);
    // for Shift in [0, 32)
    const shrSH = (h, l, s) => h >>> s;
    const shrSL = (h, l, s) => (h << (32 - s)) | (l >>> s);
    // Right rotate for Shift in [1, 32)
    const rotrSH = (h, l, s) => (h >>> s) | (l << (32 - s));
    const rotrSL = (h, l, s) => (h << (32 - s)) | (l >>> s);
    // Right rotate for Shift in (32, 64), NOTE: 32 is special case.
    const rotrBH = (h, l, s) => (h << (64 - s)) | (l >>> (s - 32));
    const rotrBL = (h, l, s) => (h >>> (s - 32)) | (l << (64 - s));
    // Right rotate for shift===32 (just swaps l&h)
    const rotr32H = (h, l) => l;
    const rotr32L = (h, l) => h;
    // Left rotate for Shift in [1, 32)
    const rotlSH = (h, l, s) => (h << s) | (l >>> (32 - s));
    const rotlSL = (h, l, s) => (l << s) | (h >>> (32 - s));
    // Left rotate for Shift in (32, 64), NOTE: 32 is special case.
    const rotlBH = (h, l, s) => (l << (s - 32)) | (h >>> (64 - s));
    const rotlBL = (h, l, s) => (h << (s - 32)) | (l >>> (64 - s));
    // JS uses 32-bit signed integers for bitwise operations which means we cannot
    // simple take carry out of low bit sum by shift, we need to use division.
    // Removing "export" has 5% perf penalty -_-
    function add(Ah, Al, Bh, Bl) {
        const l = (Al >>> 0) + (Bl >>> 0);
        return { h: (Ah + Bh + ((l / 2 ** 32) | 0)) | 0, l: l | 0 };
    }
    // Addition with more than 2 elements
    const add3L = (Al, Bl, Cl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0);
    const add3H = (low, Ah, Bh, Ch) => (Ah + Bh + Ch + ((low / 2 ** 32) | 0)) | 0;
    const add4L = (Al, Bl, Cl, Dl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0);
    const add4H = (low, Ah, Bh, Ch, Dh) => (Ah + Bh + Ch + Dh + ((low / 2 ** 32) | 0)) | 0;
    const add5L = (Al, Bl, Cl, Dl, El) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0) + (El >>> 0);
    const add5H = (low, Ah, Bh, Ch, Dh, Eh) => (Ah + Bh + Ch + Dh + Eh + ((low / 2 ** 32) | 0)) | 0;
    // prettier-ignore
    const u64 = {
        fromBig, split, toBig,
        shrSH, shrSL,
        rotrSH, rotrSL, rotrBH, rotrBL,
        rotr32H, rotr32L,
        rotlSH, rotlSL, rotlBH, rotlBL,
        add, add3L, add3H, add4L, add4H, add5H, add5L,
    };

    // Round contants (first 32 bits of the fractional parts of the cube roots of the first 80 primes 2..409):
    // prettier-ignore
    const [SHA512_Kh, SHA512_Kl] = u64.split([
        '0x428a2f98d728ae22', '0x7137449123ef65cd', '0xb5c0fbcfec4d3b2f', '0xe9b5dba58189dbbc',
        '0x3956c25bf348b538', '0x59f111f1b605d019', '0x923f82a4af194f9b', '0xab1c5ed5da6d8118',
        '0xd807aa98a3030242', '0x12835b0145706fbe', '0x243185be4ee4b28c', '0x550c7dc3d5ffb4e2',
        '0x72be5d74f27b896f', '0x80deb1fe3b1696b1', '0x9bdc06a725c71235', '0xc19bf174cf692694',
        '0xe49b69c19ef14ad2', '0xefbe4786384f25e3', '0x0fc19dc68b8cd5b5', '0x240ca1cc77ac9c65',
        '0x2de92c6f592b0275', '0x4a7484aa6ea6e483', '0x5cb0a9dcbd41fbd4', '0x76f988da831153b5',
        '0x983e5152ee66dfab', '0xa831c66d2db43210', '0xb00327c898fb213f', '0xbf597fc7beef0ee4',
        '0xc6e00bf33da88fc2', '0xd5a79147930aa725', '0x06ca6351e003826f', '0x142929670a0e6e70',
        '0x27b70a8546d22ffc', '0x2e1b21385c26c926', '0x4d2c6dfc5ac42aed', '0x53380d139d95b3df',
        '0x650a73548baf63de', '0x766a0abb3c77b2a8', '0x81c2c92e47edaee6', '0x92722c851482353b',
        '0xa2bfe8a14cf10364', '0xa81a664bbc423001', '0xc24b8b70d0f89791', '0xc76c51a30654be30',
        '0xd192e819d6ef5218', '0xd69906245565a910', '0xf40e35855771202a', '0x106aa07032bbd1b8',
        '0x19a4c116b8d2d0c8', '0x1e376c085141ab53', '0x2748774cdf8eeb99', '0x34b0bcb5e19b48a8',
        '0x391c0cb3c5c95a63', '0x4ed8aa4ae3418acb', '0x5b9cca4f7763e373', '0x682e6ff3d6b2b8a3',
        '0x748f82ee5defb2fc', '0x78a5636f43172f60', '0x84c87814a1f0ab72', '0x8cc702081a6439ec',
        '0x90befffa23631e28', '0xa4506cebde82bde9', '0xbef9a3f7b2c67915', '0xc67178f2e372532b',
        '0xca273eceea26619c', '0xd186b8c721c0c207', '0xeada7dd6cde0eb1e', '0xf57d4f7fee6ed178',
        '0x06f067aa72176fba', '0x0a637dc5a2c898a6', '0x113f9804bef90dae', '0x1b710b35131c471b',
        '0x28db77f523047d84', '0x32caab7b40c72493', '0x3c9ebe0a15c9bebc', '0x431d67c49c100d4c',
        '0x4cc5d4becb3e42b6', '0x597f299cfc657e2a', '0x5fcb6fab3ad6faec', '0x6c44198c4a475817'
    ].map(n => BigInt(n)));
    // Temporary buffer, not used to store anything between runs
    const SHA512_W_H = new Uint32Array(80);
    const SHA512_W_L = new Uint32Array(80);
    class SHA512 extends SHA2$1 {
        constructor() {
            super(128, 64, 16, false);
            // We cannot use array here since array allows indexing by variable which means optimizer/compiler cannot use registers.
            // Also looks cleaner and easier to verify with spec.
            // Initial state (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
            // h -- high 32 bits, l -- low 32 bits
            this.Ah = 0x6a09e667 | 0;
            this.Al = 0xf3bcc908 | 0;
            this.Bh = 0xbb67ae85 | 0;
            this.Bl = 0x84caa73b | 0;
            this.Ch = 0x3c6ef372 | 0;
            this.Cl = 0xfe94f82b | 0;
            this.Dh = 0xa54ff53a | 0;
            this.Dl = 0x5f1d36f1 | 0;
            this.Eh = 0x510e527f | 0;
            this.El = 0xade682d1 | 0;
            this.Fh = 0x9b05688c | 0;
            this.Fl = 0x2b3e6c1f | 0;
            this.Gh = 0x1f83d9ab | 0;
            this.Gl = 0xfb41bd6b | 0;
            this.Hh = 0x5be0cd19 | 0;
            this.Hl = 0x137e2179 | 0;
        }
        // prettier-ignore
        get() {
            const { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
            return [Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl];
        }
        // prettier-ignore
        set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl) {
            this.Ah = Ah | 0;
            this.Al = Al | 0;
            this.Bh = Bh | 0;
            this.Bl = Bl | 0;
            this.Ch = Ch | 0;
            this.Cl = Cl | 0;
            this.Dh = Dh | 0;
            this.Dl = Dl | 0;
            this.Eh = Eh | 0;
            this.El = El | 0;
            this.Fh = Fh | 0;
            this.Fl = Fl | 0;
            this.Gh = Gh | 0;
            this.Gl = Gl | 0;
            this.Hh = Hh | 0;
            this.Hl = Hl | 0;
        }
        process(view, offset) {
            // Extend the first 16 words into the remaining 64 words w[16..79] of the message schedule array
            for (let i = 0; i < 16; i++, offset += 4) {
                SHA512_W_H[i] = view.getUint32(offset);
                SHA512_W_L[i] = view.getUint32((offset += 4));
            }
            for (let i = 16; i < 80; i++) {
                // s0 := (w[i-15] rightrotate 1) xor (w[i-15] rightrotate 8) xor (w[i-15] rightshift 7)
                const W15h = SHA512_W_H[i - 15] | 0;
                const W15l = SHA512_W_L[i - 15] | 0;
                const s0h = u64.rotrSH(W15h, W15l, 1) ^ u64.rotrSH(W15h, W15l, 8) ^ u64.shrSH(W15h, W15l, 7);
                const s0l = u64.rotrSL(W15h, W15l, 1) ^ u64.rotrSL(W15h, W15l, 8) ^ u64.shrSL(W15h, W15l, 7);
                // s1 := (w[i-2] rightrotate 19) xor (w[i-2] rightrotate 61) xor (w[i-2] rightshift 6)
                const W2h = SHA512_W_H[i - 2] | 0;
                const W2l = SHA512_W_L[i - 2] | 0;
                const s1h = u64.rotrSH(W2h, W2l, 19) ^ u64.rotrBH(W2h, W2l, 61) ^ u64.shrSH(W2h, W2l, 6);
                const s1l = u64.rotrSL(W2h, W2l, 19) ^ u64.rotrBL(W2h, W2l, 61) ^ u64.shrSL(W2h, W2l, 6);
                // SHA256_W[i] = s0 + s1 + SHA256_W[i - 7] + SHA256_W[i - 16];
                const SUMl = u64.add4L(s0l, s1l, SHA512_W_L[i - 7], SHA512_W_L[i - 16]);
                const SUMh = u64.add4H(SUMl, s0h, s1h, SHA512_W_H[i - 7], SHA512_W_H[i - 16]);
                SHA512_W_H[i] = SUMh | 0;
                SHA512_W_L[i] = SUMl | 0;
            }
            let { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
            // Compression function main loop, 80 rounds
            for (let i = 0; i < 80; i++) {
                // S1 := (e rightrotate 14) xor (e rightrotate 18) xor (e rightrotate 41)
                const sigma1h = u64.rotrSH(Eh, El, 14) ^ u64.rotrSH(Eh, El, 18) ^ u64.rotrBH(Eh, El, 41);
                const sigma1l = u64.rotrSL(Eh, El, 14) ^ u64.rotrSL(Eh, El, 18) ^ u64.rotrBL(Eh, El, 41);
                //const T1 = (H + sigma1 + Chi(E, F, G) + SHA256_K[i] + SHA256_W[i]) | 0;
                const CHIh = (Eh & Fh) ^ (~Eh & Gh);
                const CHIl = (El & Fl) ^ (~El & Gl);
                // T1 = H + sigma1 + Chi(E, F, G) + SHA512_K[i] + SHA512_W[i]
                // prettier-ignore
                const T1ll = u64.add5L(Hl, sigma1l, CHIl, SHA512_Kl[i], SHA512_W_L[i]);
                const T1h = u64.add5H(T1ll, Hh, sigma1h, CHIh, SHA512_Kh[i], SHA512_W_H[i]);
                const T1l = T1ll | 0;
                // S0 := (a rightrotate 28) xor (a rightrotate 34) xor (a rightrotate 39)
                const sigma0h = u64.rotrSH(Ah, Al, 28) ^ u64.rotrBH(Ah, Al, 34) ^ u64.rotrBH(Ah, Al, 39);
                const sigma0l = u64.rotrSL(Ah, Al, 28) ^ u64.rotrBL(Ah, Al, 34) ^ u64.rotrBL(Ah, Al, 39);
                const MAJh = (Ah & Bh) ^ (Ah & Ch) ^ (Bh & Ch);
                const MAJl = (Al & Bl) ^ (Al & Cl) ^ (Bl & Cl);
                Hh = Gh | 0;
                Hl = Gl | 0;
                Gh = Fh | 0;
                Gl = Fl | 0;
                Fh = Eh | 0;
                Fl = El | 0;
                ({ h: Eh, l: El } = u64.add(Dh | 0, Dl | 0, T1h | 0, T1l | 0));
                Dh = Ch | 0;
                Dl = Cl | 0;
                Ch = Bh | 0;
                Cl = Bl | 0;
                Bh = Ah | 0;
                Bl = Al | 0;
                const All = u64.add3L(T1l, sigma0l, MAJl);
                Ah = u64.add3H(All, T1h, sigma0h, MAJh);
                Al = All | 0;
            }
            // Add the compressed chunk to the current hash value
            ({ h: Ah, l: Al } = u64.add(this.Ah | 0, this.Al | 0, Ah | 0, Al | 0));
            ({ h: Bh, l: Bl } = u64.add(this.Bh | 0, this.Bl | 0, Bh | 0, Bl | 0));
            ({ h: Ch, l: Cl } = u64.add(this.Ch | 0, this.Cl | 0, Ch | 0, Cl | 0));
            ({ h: Dh, l: Dl } = u64.add(this.Dh | 0, this.Dl | 0, Dh | 0, Dl | 0));
            ({ h: Eh, l: El } = u64.add(this.Eh | 0, this.El | 0, Eh | 0, El | 0));
            ({ h: Fh, l: Fl } = u64.add(this.Fh | 0, this.Fl | 0, Fh | 0, Fl | 0));
            ({ h: Gh, l: Gl } = u64.add(this.Gh | 0, this.Gl | 0, Gh | 0, Gl | 0));
            ({ h: Hh, l: Hl } = u64.add(this.Hh | 0, this.Hl | 0, Hh | 0, Hl | 0));
            this.set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl);
        }
        roundClean() {
            SHA512_W_H.fill(0);
            SHA512_W_L.fill(0);
        }
        destroy() {
            this.buffer.fill(0);
            this.set(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        }
    }
    class SHA512_224 extends SHA512 {
        constructor() {
            super();
            // h -- high 32 bits, l -- low 32 bits
            this.Ah = 0x8c3d37c8 | 0;
            this.Al = 0x19544da2 | 0;
            this.Bh = 0x73e19966 | 0;
            this.Bl = 0x89dcd4d6 | 0;
            this.Ch = 0x1dfab7ae | 0;
            this.Cl = 0x32ff9c82 | 0;
            this.Dh = 0x679dd514 | 0;
            this.Dl = 0x582f9fcf | 0;
            this.Eh = 0x0f6d2b69 | 0;
            this.El = 0x7bd44da8 | 0;
            this.Fh = 0x77e36f73 | 0;
            this.Fl = 0x04c48942 | 0;
            this.Gh = 0x3f9d85a8 | 0;
            this.Gl = 0x6a1d36c8 | 0;
            this.Hh = 0x1112e6ad | 0;
            this.Hl = 0x91d692a1 | 0;
            this.outputLen = 28;
        }
    }
    class SHA512_256 extends SHA512 {
        constructor() {
            super();
            // h -- high 32 bits, l -- low 32 bits
            this.Ah = 0x22312194 | 0;
            this.Al = 0xfc2bf72c | 0;
            this.Bh = 0x9f555fa3 | 0;
            this.Bl = 0xc84c64c2 | 0;
            this.Ch = 0x2393b86b | 0;
            this.Cl = 0x6f53b151 | 0;
            this.Dh = 0x96387719 | 0;
            this.Dl = 0x5940eabd | 0;
            this.Eh = 0x96283ee2 | 0;
            this.El = 0xa88effe3 | 0;
            this.Fh = 0xbe5e1e25 | 0;
            this.Fl = 0x53863992 | 0;
            this.Gh = 0x2b0199fc | 0;
            this.Gl = 0x2c85b8aa | 0;
            this.Hh = 0x0eb72ddc | 0;
            this.Hl = 0x81c52ca2 | 0;
            this.outputLen = 32;
        }
    }
    class SHA384 extends SHA512 {
        constructor() {
            super();
            // h -- high 32 bits, l -- low 32 bits
            this.Ah = 0xcbbb9d5d | 0;
            this.Al = 0xc1059ed8 | 0;
            this.Bh = 0x629a292a | 0;
            this.Bl = 0x367cd507 | 0;
            this.Ch = 0x9159015a | 0;
            this.Cl = 0x3070dd17 | 0;
            this.Dh = 0x152fecd8 | 0;
            this.Dl = 0xf70e5939 | 0;
            this.Eh = 0x67332667 | 0;
            this.El = 0xffc00b31 | 0;
            this.Fh = 0x8eb44a87 | 0;
            this.Fl = 0x68581511 | 0;
            this.Gh = 0xdb0c2e0d | 0;
            this.Gl = 0x64f98fa7 | 0;
            this.Hh = 0x47b5481d | 0;
            this.Hl = 0xbefa4fa4 | 0;
            this.outputLen = 48;
        }
    }
    const sha512 = wrapConstructor$1(() => new SHA512());
    wrapConstructor$1(() => new SHA512_224());
    wrapConstructor$1(() => new SHA512_256());
    wrapConstructor$1(() => new SHA384());

    utils$1.hmacSha256Sync = (key, ...msgs) => hmac$1(sha256$1, key, utils$1.concatBytes(...msgs));
    const base58check = base58check$1(sha256$1);
    function bytesToNumber(bytes) {
        return BigInt(`0x${bytesToHex$1(bytes)}`);
    }
    function numberToBytes(num) {
        return hexToBytes(num.toString(16).padStart(64, '0'));
    }
    const MASTER_SECRET = utf8ToBytes$1('Bitcoin seed');
    const BITCOIN_VERSIONS = { private: 0x0488ade4, public: 0x0488b21e };
    const HARDENED_OFFSET = 0x80000000;
    const hash160 = (data) => ripemd160(sha256$1(data));
    const fromU32 = (data) => createView$1(data).getUint32(0, false);
    const toU32 = (n) => {
        if (!Number.isSafeInteger(n) || n < 0 || n > 2 ** 32 - 1) {
            throw new Error(`Invalid number=${n}. Should be from 0 to 2 ** 32 - 1`);
        }
        const buf = new Uint8Array(4);
        createView$1(buf).setUint32(0, n, false);
        return buf;
    };
    class HDKey {
        constructor(opt) {
            this.depth = 0;
            this.index = 0;
            this.chainCode = null;
            this.parentFingerprint = 0;
            if (!opt || typeof opt !== 'object') {
                throw new Error('HDKey.constructor must not be called directly');
            }
            this.versions = opt.versions || BITCOIN_VERSIONS;
            this.depth = opt.depth || 0;
            this.chainCode = opt.chainCode;
            this.index = opt.index || 0;
            this.parentFingerprint = opt.parentFingerprint || 0;
            if (!this.depth) {
                if (this.parentFingerprint || this.index) {
                    throw new Error('HDKey: zero depth with non-zero index/parent fingerprint');
                }
            }
            if (opt.publicKey && opt.privateKey) {
                throw new Error('HDKey: publicKey and privateKey at same time.');
            }
            if (opt.privateKey) {
                if (!utils$1.isValidPrivateKey(opt.privateKey)) {
                    throw new Error('Invalid private key');
                }
                this.privKey =
                    typeof opt.privateKey === 'bigint' ? opt.privateKey : bytesToNumber(opt.privateKey);
                this.privKeyBytes = numberToBytes(this.privKey);
                this.pubKey = getPublicKey$1(opt.privateKey, true);
            }
            else if (opt.publicKey) {
                this.pubKey = Point.fromHex(opt.publicKey).toRawBytes(true);
            }
            else {
                throw new Error('HDKey: no public or private key provided');
            }
            this.pubHash = hash160(this.pubKey);
        }
        get fingerprint() {
            if (!this.pubHash) {
                throw new Error('No publicKey set!');
            }
            return fromU32(this.pubHash);
        }
        get identifier() {
            return this.pubHash;
        }
        get pubKeyHash() {
            return this.pubHash;
        }
        get privateKey() {
            return this.privKeyBytes || null;
        }
        get publicKey() {
            return this.pubKey || null;
        }
        get privateExtendedKey() {
            const priv = this.privateKey;
            if (!priv) {
                throw new Error('No private key');
            }
            return base58check.encode(this.serialize(this.versions.private, concatBytes(new Uint8Array([0]), priv)));
        }
        get publicExtendedKey() {
            if (!this.pubKey) {
                throw new Error('No public key');
            }
            return base58check.encode(this.serialize(this.versions.public, this.pubKey));
        }
        static fromMasterSeed(seed, versions = BITCOIN_VERSIONS) {
            bytes$1(seed);
            if (8 * seed.length < 128 || 8 * seed.length > 512) {
                throw new Error(`HDKey: wrong seed length=${seed.length}. Should be between 128 and 512 bits; 256 bits is advised)`);
            }
            const I = hmac$1(sha512, MASTER_SECRET, seed);
            return new HDKey({
                versions,
                chainCode: I.slice(32),
                privateKey: I.slice(0, 32),
            });
        }
        static fromExtendedKey(base58key, versions = BITCOIN_VERSIONS) {
            const keyBuffer = base58check.decode(base58key);
            const keyView = createView$1(keyBuffer);
            const version = keyView.getUint32(0, false);
            const opt = {
                versions,
                depth: keyBuffer[4],
                parentFingerprint: keyView.getUint32(5, false),
                index: keyView.getUint32(9, false),
                chainCode: keyBuffer.slice(13, 45),
            };
            const key = keyBuffer.slice(45);
            const isPriv = key[0] === 0;
            if (version !== versions[isPriv ? 'private' : 'public']) {
                throw new Error('Version mismatch');
            }
            if (isPriv) {
                return new HDKey({ ...opt, privateKey: key.slice(1) });
            }
            else {
                return new HDKey({ ...opt, publicKey: key });
            }
        }
        static fromJSON(json) {
            return HDKey.fromExtendedKey(json.xpriv);
        }
        derive(path) {
            if (!/^[mM]'?/.test(path)) {
                throw new Error('Path must start with "m" or "M"');
            }
            if (/^[mM]'?$/.test(path)) {
                return this;
            }
            const parts = path.replace(/^[mM]'?\//, '').split('/');
            let child = this;
            for (const c of parts) {
                const m = /^(\d+)('?)$/.exec(c);
                if (!m || m.length !== 3) {
                    throw new Error(`Invalid child index: ${c}`);
                }
                let idx = +m[1];
                if (!Number.isSafeInteger(idx) || idx >= HARDENED_OFFSET) {
                    throw new Error('Invalid index');
                }
                if (m[2] === "'") {
                    idx += HARDENED_OFFSET;
                }
                child = child.deriveChild(idx);
            }
            return child;
        }
        deriveChild(index) {
            if (!this.pubKey || !this.chainCode) {
                throw new Error('No publicKey or chainCode set');
            }
            let data = toU32(index);
            if (index >= HARDENED_OFFSET) {
                const priv = this.privateKey;
                if (!priv) {
                    throw new Error('Could not derive hardened child key');
                }
                data = concatBytes(new Uint8Array([0]), priv, data);
            }
            else {
                data = concatBytes(this.pubKey, data);
            }
            const I = hmac$1(sha512, this.chainCode, data);
            const childTweak = bytesToNumber(I.slice(0, 32));
            const chainCode = I.slice(32);
            if (!utils$1.isValidPrivateKey(childTweak)) {
                throw new Error('Tweak bigger than curve order');
            }
            const opt = {
                versions: this.versions,
                chainCode,
                depth: this.depth + 1,
                parentFingerprint: this.fingerprint,
                index,
            };
            try {
                if (this.privateKey) {
                    const added = utils$1.mod(this.privKey + childTweak, CURVE.n);
                    if (!utils$1.isValidPrivateKey(added)) {
                        throw new Error('The tweak was out of range or the resulted private key is invalid');
                    }
                    opt.privateKey = added;
                }
                else {
                    const added = Point.fromHex(this.pubKey).add(Point.fromPrivateKey(childTweak));
                    if (added.equals(Point.ZERO)) {
                        throw new Error('The tweak was equal to negative P, which made the result key invalid');
                    }
                    opt.publicKey = added.toRawBytes(true);
                }
                return new HDKey(opt);
            }
            catch (err) {
                return this.deriveChild(index + 1);
            }
        }
        sign(hash) {
            if (!this.privateKey) {
                throw new Error('No privateKey set!');
            }
            bytes$1(hash, 32);
            return signSync(hash, this.privKey, {
                canonical: true,
                der: false,
            });
        }
        verify(hash, signature) {
            bytes$1(hash, 32);
            bytes$1(signature, 64);
            if (!this.publicKey) {
                throw new Error('No publicKey set!');
            }
            let sig;
            try {
                sig = Signature.fromCompact(signature);
            }
            catch (error) {
                return false;
            }
            return verify(sig, hash, this.publicKey);
        }
        wipePrivateData() {
            this.privKey = undefined;
            if (this.privKeyBytes) {
                this.privKeyBytes.fill(0);
                this.privKeyBytes = undefined;
            }
            return this;
        }
        toJSON() {
            return {
                xpriv: this.privateExtendedKey,
                xpub: this.publicExtendedKey,
            };
        }
        serialize(version, key) {
            if (!this.chainCode) {
                throw new Error('No chainCode set');
            }
            bytes$1(key, 33);
            return concatBytes(toU32(version), new Uint8Array([this.depth]), toU32(this.parentFingerprint), toU32(this.index), this.chainCode, key);
        }
    }

    // HMAC (RFC 2104)
    class HMAC extends Hash$2 {
        constructor(hash, _key) {
            super();
            this.finished = false;
            this.destroyed = false;
            assert$4.hash(hash);
            const key = toBytes$2(_key);
            this.iHash = hash.create();
            if (typeof this.iHash.update !== 'function')
                throw new TypeError('Expected instance of class which extends utils.Hash');
            this.blockLen = this.iHash.blockLen;
            this.outputLen = this.iHash.outputLen;
            const blockLen = this.blockLen;
            const pad = new Uint8Array(blockLen);
            // blockLen can be bigger than outputLen
            pad.set(key.length > blockLen ? hash.create().update(key).digest() : key);
            for (let i = 0; i < pad.length; i++)
                pad[i] ^= 0x36;
            this.iHash.update(pad);
            // By doing update (processing of first block) of outer hash here we can re-use it between multiple calls via clone
            this.oHash = hash.create();
            // Undo internal XOR && apply outer XOR
            for (let i = 0; i < pad.length; i++)
                pad[i] ^= 0x36 ^ 0x5c;
            this.oHash.update(pad);
            pad.fill(0);
        }
        update(buf) {
            assert$4.exists(this);
            this.iHash.update(buf);
            return this;
        }
        digestInto(out) {
            assert$4.exists(this);
            assert$4.bytes(out, this.outputLen);
            this.finished = true;
            this.iHash.digestInto(out);
            this.oHash.update(out);
            this.oHash.digestInto(out);
            this.destroy();
        }
        digest() {
            const out = new Uint8Array(this.oHash.outputLen);
            this.digestInto(out);
            return out;
        }
        _cloneInto(to) {
            // Create new instance without calling constructor since key already in state and we don't know it.
            to || (to = Object.create(Object.getPrototypeOf(this), {}));
            const { oHash, iHash, finished, destroyed, blockLen, outputLen } = this;
            to = to;
            to.finished = finished;
            to.destroyed = destroyed;
            to.blockLen = blockLen;
            to.outputLen = outputLen;
            to.oHash = oHash._cloneInto(to.oHash);
            to.iHash = iHash._cloneInto(to.iHash);
            return to;
        }
        destroy() {
            this.destroyed = true;
            this.oHash.destroy();
            this.iHash.destroy();
        }
    }
    /**
     * HMAC: RFC2104 message authentication code.
     * @param hash - function that would be used e.g. sha256
     * @param key - message key
     * @param message - message data
     */
    const hmac = (hash, key, message) => new HMAC(hash, key).update(message).digest();
    hmac.create = (hash, key) => new HMAC(hash, key);

    var __defProp = Object.defineProperty;
    var __export = (target, all) => {
      for (var name in all)
        __defProp(target, name, { get: all[name], enumerable: true });
    };
    function getPublicKey(privateKey) {
      return utils$1.bytesToHex(schnorr.getPublicKey(privateKey));
    }

    // utils.ts
    var utils_exports = {};
    __export(utils_exports, {
      insertEventIntoAscendingList: () => insertEventIntoAscendingList,
      insertEventIntoDescendingList: () => insertEventIntoDescendingList,
      normalizeURL: () => normalizeURL,
      utf8Decoder: () => utf8Decoder,
      utf8Encoder: () => utf8Encoder$1
    });
    var utf8Decoder = new TextDecoder("utf-8");
    var utf8Encoder$1 = new TextEncoder();
    function normalizeURL(url) {
      let p = new URL(url);
      p.pathname = p.pathname.replace(/\/+/g, "/");
      if (p.pathname.endsWith("/"))
        p.pathname = p.pathname.slice(0, -1);
      if (p.port === "80" && p.protocol === "ws:" || p.port === "443" && p.protocol === "wss:")
        p.port = "";
      p.searchParams.sort();
      p.hash = "";
      return p.toString();
    }
    function insertEventIntoDescendingList(sortedArray, event) {
      let start = 0;
      let end = sortedArray.length - 1;
      let midPoint;
      let position = start;
      if (end < 0) {
        position = 0;
      } else if (event.created_at < sortedArray[end].created_at) {
        position = end + 1;
      } else if (event.created_at >= sortedArray[start].created_at) {
        position = start;
      } else
        while (true) {
          if (end <= start + 1) {
            position = end;
            break;
          }
          midPoint = Math.floor(start + (end - start) / 2);
          if (sortedArray[midPoint].created_at > event.created_at) {
            start = midPoint;
          } else if (sortedArray[midPoint].created_at < event.created_at) {
            end = midPoint;
          } else {
            position = midPoint;
            break;
          }
        }
      if (sortedArray[position]?.id !== event.id) {
        return [
          ...sortedArray.slice(0, position),
          event,
          ...sortedArray.slice(position)
        ];
      }
      return sortedArray;
    }
    function insertEventIntoAscendingList(sortedArray, event) {
      let start = 0;
      let end = sortedArray.length - 1;
      let midPoint;
      let position = start;
      if (end < 0) {
        position = 0;
      } else if (event.created_at > sortedArray[end].created_at) {
        position = end + 1;
      } else if (event.created_at <= sortedArray[start].created_at) {
        position = start;
      } else
        while (true) {
          if (end <= start + 1) {
            position = end;
            break;
          }
          midPoint = Math.floor(start + (end - start) / 2);
          if (sortedArray[midPoint].created_at < event.created_at) {
            start = midPoint;
          } else if (sortedArray[midPoint].created_at > event.created_at) {
            end = midPoint;
          } else {
            position = midPoint;
            break;
          }
        }
      if (sortedArray[position]?.id !== event.id) {
        return [
          ...sortedArray.slice(0, position),
          event,
          ...sortedArray.slice(position)
        ];
      }
      return sortedArray;
    }
    function serializeEvent(evt) {
      if (!validateEvent(evt))
        throw new Error("can't serialize event with wrong or missing properties");
      return JSON.stringify([
        0,
        evt.pubkey,
        evt.created_at,
        evt.kind,
        evt.tags,
        evt.content
      ]);
    }
    function getEventHash(event) {
      let eventHash = sha256$3(utf8Encoder$1.encode(serializeEvent(event)));
      return utils$1.bytesToHex(eventHash);
    }
    var isRecord = (obj) => obj instanceof Object;
    function validateEvent(event) {
      if (!isRecord(event))
        return false;
      if (typeof event.kind !== "number")
        return false;
      if (typeof event.content !== "string")
        return false;
      if (typeof event.created_at !== "number")
        return false;
      if (typeof event.pubkey !== "string")
        return false;
      if (!event.pubkey.match(/^[a-f0-9]{64}$/))
        return false;
      if (!Array.isArray(event.tags))
        return false;
      for (let i = 0; i < event.tags.length; i++) {
        let tag = event.tags[i];
        if (!Array.isArray(tag))
          return false;
        for (let j = 0; j < tag.length; j++) {
          if (typeof tag[j] === "object")
            return false;
        }
      }
      return true;
    }
    function verifySignature(event) {
      return schnorr.verifySync(
        event.sig,
        getEventHash(event),
        event.pubkey
      );
    }
    function signEvent(event, key) {
      return utils$1.bytesToHex(
        schnorr.signSync(getEventHash(event), key)
      );
    }

    // filter.ts
    function matchFilter(filter, event) {
      if (filter.ids && filter.ids.indexOf(event.id) === -1) {
        if (!filter.ids.some((prefix) => event.id.startsWith(prefix))) {
          return false;
        }
      }
      if (filter.kinds && filter.kinds.indexOf(event.kind) === -1)
        return false;
      if (filter.authors && filter.authors.indexOf(event.pubkey) === -1) {
        if (!filter.authors.some((prefix) => event.pubkey.startsWith(prefix))) {
          return false;
        }
      }
      for (let f in filter) {
        if (f[0] === "#") {
          let tagName = f.slice(1);
          let values = filter[`#${tagName}`];
          if (values && !event.tags.find(
            ([t, v]) => t === f.slice(1) && values.indexOf(v) !== -1
          ))
            return false;
        }
      }
      if (filter.since && event.created_at < filter.since)
        return false;
      if (filter.until && event.created_at >= filter.until)
        return false;
      return true;
    }
    function matchFilters(filters, event) {
      for (let i = 0; i < filters.length; i++) {
        if (matchFilter(filters[i], event))
          return true;
      }
      return false;
    }

    // fakejson.ts
    var fakejson_exports = {};
    __export(fakejson_exports, {
      getHex64: () => getHex64,
      getInt: () => getInt,
      getSubscriptionId: () => getSubscriptionId,
      matchEventId: () => matchEventId,
      matchEventKind: () => matchEventKind,
      matchEventPubkey: () => matchEventPubkey
    });
    function getHex64(json, field) {
      let len = field.length + 3;
      let idx = json.indexOf(`"${field}":`) + len;
      let s = json.slice(idx).indexOf(`"`) + idx + 1;
      return json.slice(s, s + 64);
    }
    function getInt(json, field) {
      let len = field.length;
      let idx = json.indexOf(`"${field}":`) + len + 3;
      let sliced = json.slice(idx);
      let end = Math.min(sliced.indexOf(","), sliced.indexOf("}"));
      return parseInt(sliced.slice(0, end), 10);
    }
    function getSubscriptionId(json) {
      let idx = json.slice(0, 22).indexOf(`"EVENT"`);
      if (idx === -1)
        return null;
      let pstart = json.slice(idx + 7 + 1).indexOf(`"`);
      if (pstart === -1)
        return null;
      let start = idx + 7 + 1 + pstart;
      let pend = json.slice(start + 1, 80).indexOf(`"`);
      if (pend === -1)
        return null;
      let end = start + 1 + pend;
      return json.slice(start + 1, end);
    }
    function matchEventId(json, id) {
      return id === getHex64(json, "id");
    }
    function matchEventPubkey(json, pubkey) {
      return pubkey === getHex64(json, "pubkey");
    }
    function matchEventKind(json, kind) {
      return kind === getInt(json, "kind");
    }

    // relay.ts
    var newListeners = () => ({
      connect: [],
      disconnect: [],
      error: [],
      notice: [],
      auth: []
    });
    function relayInit(url, options = {}) {
      let { listTimeout = 3e3, getTimeout = 3e3, countTimeout = 3e3 } = options;
      var ws;
      var openSubs = {};
      var listeners = newListeners();
      var subListeners = {};
      var pubListeners = {};
      var connectionPromise;
      async function connectRelay() {
        if (connectionPromise)
          return connectionPromise;
        connectionPromise = new Promise((resolve, reject) => {
          try {
            ws = new WebSocket(url);
          } catch (err) {
            reject(err);
          }
          ws.onopen = () => {
            listeners.connect.forEach((cb) => cb());
            resolve();
          };
          ws.onerror = () => {
            connectionPromise = void 0;
            listeners.error.forEach((cb) => cb());
            reject();
          };
          ws.onclose = async () => {
            connectionPromise = void 0;
            listeners.disconnect.forEach((cb) => cb());
          };
          let incomingMessageQueue = [];
          let handleNextInterval;
          ws.onmessage = (e) => {
            incomingMessageQueue.push(e.data);
            if (!handleNextInterval) {
              handleNextInterval = setInterval(handleNext, 0);
            }
          };
          function handleNext() {
            if (incomingMessageQueue.length === 0) {
              clearInterval(handleNextInterval);
              handleNextInterval = null;
              return;
            }
            var json = incomingMessageQueue.shift();
            if (!json)
              return;
            let subid = getSubscriptionId(json);
            if (subid) {
              let so = openSubs[subid];
              if (so && so.alreadyHaveEvent && so.alreadyHaveEvent(getHex64(json, "id"), url)) {
                return;
              }
            }
            try {
              let data = JSON.parse(json);
              switch (data[0]) {
                case "EVENT": {
                  let id2 = data[1];
                  let event = data[2];
                  if (validateEvent(event) && openSubs[id2] && (openSubs[id2].skipVerification || verifySignature(event)) && matchFilters(openSubs[id2].filters, event)) {
                    openSubs[id2];
                    (subListeners[id2]?.event || []).forEach((cb) => cb(event));
                  }
                  return;
                }
                case "COUNT":
                  let id = data[1];
                  let payload = data[2];
                  if (openSubs[id]) {
                    ;
                    (subListeners[id]?.count || []).forEach((cb) => cb(payload));
                  }
                  return;
                case "EOSE": {
                  let id2 = data[1];
                  if (id2 in subListeners) {
                    subListeners[id2].eose.forEach((cb) => cb());
                    subListeners[id2].eose = [];
                  }
                  return;
                }
                case "OK": {
                  let id2 = data[1];
                  let ok = data[2];
                  let reason = data[3] || "";
                  if (id2 in pubListeners) {
                    if (ok)
                      pubListeners[id2].ok.forEach((cb) => cb());
                    else
                      pubListeners[id2].failed.forEach((cb) => cb(reason));
                    pubListeners[id2].ok = [];
                    pubListeners[id2].failed = [];
                  }
                  return;
                }
                case "NOTICE":
                  let notice = data[1];
                  listeners.notice.forEach((cb) => cb(notice));
                  return;
                case "AUTH": {
                  let challenge = data[1];
                  listeners.auth?.forEach((cb) => cb(challenge));
                  return;
                }
              }
            } catch (err) {
              return;
            }
          }
        });
        return connectionPromise;
      }
      function connected() {
        return ws?.readyState === 1;
      }
      async function connect() {
        if (connected())
          return;
        await connectRelay();
      }
      async function trySend(params) {
        let msg = JSON.stringify(params);
        if (!connected()) {
          await new Promise((resolve) => setTimeout(resolve, 1e3));
          if (!connected()) {
            return;
          }
        }
        try {
          ws.send(msg);
        } catch (err) {
          console.log(err);
        }
      }
      const sub = (filters, {
        verb = "REQ",
        skipVerification = false,
        alreadyHaveEvent = null,
        id = Math.random().toString().slice(2)
      } = {}) => {
        let subid = id;
        openSubs[subid] = {
          id: subid,
          filters,
          skipVerification,
          alreadyHaveEvent
        };
        trySend([verb, subid, ...filters]);
        return {
          sub: (newFilters, newOpts = {}) => sub(newFilters || filters, {
            skipVerification: newOpts.skipVerification || skipVerification,
            alreadyHaveEvent: newOpts.alreadyHaveEvent || alreadyHaveEvent,
            id: subid
          }),
          unsub: () => {
            delete openSubs[subid];
            delete subListeners[subid];
            trySend(["CLOSE", subid]);
          },
          on: (type, cb) => {
            subListeners[subid] = subListeners[subid] || {
              event: [],
              count: [],
              eose: []
            };
            subListeners[subid][type].push(cb);
          },
          off: (type, cb) => {
            let listeners2 = subListeners[subid];
            let idx = listeners2[type].indexOf(cb);
            if (idx >= 0)
              listeners2[type].splice(idx, 1);
          }
        };
      };
      function _publishEvent(event, type) {
        if (!event.id)
          throw new Error(`event ${event} has no id`);
        let id = event.id;
        trySend([type, event]);
        return {
          on: (type2, cb) => {
            pubListeners[id] = pubListeners[id] || {
              ok: [],
              failed: []
            };
            pubListeners[id][type2].push(cb);
          },
          off: (type2, cb) => {
            let listeners2 = pubListeners[id];
            if (!listeners2)
              return;
            let idx = listeners2[type2].indexOf(cb);
            if (idx >= 0)
              listeners2[type2].splice(idx, 1);
          }
        };
      }
      return {
        url,
        sub,
        on: (type, cb) => {
          listeners[type].push(cb);
          if (type === "connect" && ws?.readyState === 1) {
            cb();
          }
        },
        off: (type, cb) => {
          let index = listeners[type].indexOf(cb);
          if (index !== -1)
            listeners[type].splice(index, 1);
        },
        list: (filters, opts) => new Promise((resolve) => {
          let s = sub(filters, opts);
          let events = [];
          let timeout = setTimeout(() => {
            s.unsub();
            resolve(events);
          }, listTimeout);
          s.on("eose", () => {
            s.unsub();
            clearTimeout(timeout);
            resolve(events);
          });
          s.on("event", (event) => {
            events.push(event);
          });
        }),
        get: (filter, opts) => new Promise((resolve) => {
          let s = sub([filter], opts);
          let timeout = setTimeout(() => {
            s.unsub();
            resolve(null);
          }, getTimeout);
          s.on("event", (event) => {
            s.unsub();
            clearTimeout(timeout);
            resolve(event);
          });
        }),
        count: (filters) => new Promise((resolve) => {
          let s = sub(filters, { ...sub, verb: "COUNT" });
          let timeout = setTimeout(() => {
            s.unsub();
            resolve(null);
          }, countTimeout);
          s.on("count", (event) => {
            s.unsub();
            clearTimeout(timeout);
            resolve(event);
          });
        }),
        publish(event) {
          return _publishEvent(event, "EVENT");
        },
        auth(event) {
          return _publishEvent(event, "AUTH");
        },
        connect,
        close() {
          listeners = newListeners();
          subListeners = {};
          pubListeners = {};
          if (ws.readyState === WebSocket.OPEN) {
            ws?.close();
          }
        },
        get status() {
          return ws?.readyState ?? 3;
        }
      };
    }

    // pool.ts
    var SimplePool = class {
      _conn;
      _seenOn = {};
      eoseSubTimeout;
      getTimeout;
      constructor(options = {}) {
        this._conn = {};
        this.eoseSubTimeout = options.eoseSubTimeout || 3400;
        this.getTimeout = options.getTimeout || 3400;
      }
      close(relays) {
        relays.forEach((url) => {
          let relay = this._conn[normalizeURL(url)];
          if (relay)
            relay.close();
        });
      }
      async ensureRelay(url) {
        const nm = normalizeURL(url);
        if (!this._conn[nm]) {
          this._conn[nm] = relayInit(nm, {
            getTimeout: this.getTimeout * 0.9,
            listTimeout: this.getTimeout * 0.9
          });
        }
        const relay = this._conn[nm];
        await relay.connect();
        return relay;
      }
      sub(relays, filters, opts) {
        let _knownIds = /* @__PURE__ */ new Set();
        let modifiedOpts = { ...opts || {} };
        modifiedOpts.alreadyHaveEvent = (id, url) => {
          if (opts?.alreadyHaveEvent?.(id, url)) {
            return true;
          }
          let set = this._seenOn[id] || /* @__PURE__ */ new Set();
          set.add(url);
          this._seenOn[id] = set;
          return _knownIds.has(id);
        };
        let subs = [];
        let eventListeners = /* @__PURE__ */ new Set();
        let eoseListeners = /* @__PURE__ */ new Set();
        let eosesMissing = relays.length;
        let eoseSent = false;
        let eoseTimeout = setTimeout(() => {
          eoseSent = true;
          for (let cb of eoseListeners.values())
            cb();
        }, this.eoseSubTimeout);
        relays.forEach(async (relay) => {
          let r;
          try {
            r = await this.ensureRelay(relay);
          } catch (err) {
            handleEose();
            return;
          }
          if (!r)
            return;
          let s = r.sub(filters, modifiedOpts);
          s.on("event", (event) => {
            _knownIds.add(event.id);
            for (let cb of eventListeners.values())
              cb(event);
          });
          s.on("eose", () => {
            if (eoseSent)
              return;
            handleEose();
          });
          subs.push(s);
          function handleEose() {
            eosesMissing--;
            if (eosesMissing === 0) {
              clearTimeout(eoseTimeout);
              for (let cb of eoseListeners.values())
                cb();
            }
          }
        });
        let greaterSub = {
          sub(filters2, opts2) {
            subs.forEach((sub) => sub.sub(filters2, opts2));
            return greaterSub;
          },
          unsub() {
            subs.forEach((sub) => sub.unsub());
          },
          on(type, cb) {
            if (type === "event") {
              eventListeners.add(cb);
            } else if (type === "eose") {
              eoseListeners.add(cb);
            }
          },
          off(type, cb) {
            if (type === "event") {
              eventListeners.delete(cb);
            } else if (type === "eose")
              eoseListeners.delete(cb);
          }
        };
        return greaterSub;
      }
      get(relays, filter, opts) {
        return new Promise((resolve) => {
          let sub = this.sub(relays, [filter], opts);
          let timeout = setTimeout(() => {
            sub.unsub();
            resolve(null);
          }, this.getTimeout);
          sub.on("event", (event) => {
            resolve(event);
            clearTimeout(timeout);
            sub.unsub();
          });
        });
      }
      list(relays, filters, opts) {
        return new Promise((resolve) => {
          let events = [];
          let sub = this.sub(relays, filters, opts);
          sub.on("event", (event) => {
            events.push(event);
          });
          sub.on("eose", () => {
            sub.unsub();
            resolve(events);
          });
        });
      }
      publish(relays, event) {
        const pubPromises = relays.map(async (relay) => {
          let r;
          try {
            r = await this.ensureRelay(relay);
            return r.publish(event);
          } catch (_) {
            return { on() {
            }, off() {
            } };
          }
        });
        const callbackMap = /* @__PURE__ */ new Map();
        return {
          on(type, cb) {
            relays.forEach(async (relay, i) => {
              let pub = await pubPromises[i];
              let callback = () => cb(relay);
              callbackMap.set(cb, callback);
              pub.on(type, callback);
            });
          },
          off(type, cb) {
            relays.forEach(async (_, i) => {
              let callback = callbackMap.get(cb);
              if (callback) {
                let pub = await pubPromises[i];
                pub.off(type, callback);
              }
            });
          }
        };
      }
      seenOn(id) {
        return Array.from(this._seenOn[id]?.values?.() || []);
      }
    };

    // nip19.ts
    var nip19_exports = {};
    __export(nip19_exports, {
      decode: () => decode,
      naddrEncode: () => naddrEncode,
      neventEncode: () => neventEncode,
      noteEncode: () => noteEncode,
      nprofileEncode: () => nprofileEncode,
      npubEncode: () => npubEncode,
      nrelayEncode: () => nrelayEncode,
      nsecEncode: () => nsecEncode
    });
    var Bech32MaxSize = 5e3;
    function decode(nip19) {
      let { prefix, words } = bech32.decode(nip19, Bech32MaxSize);
      let data = new Uint8Array(bech32.fromWords(words));
      switch (prefix) {
        case "nprofile": {
          let tlv = parseTLV(data);
          if (!tlv[0]?.[0])
            throw new Error("missing TLV 0 for nprofile");
          if (tlv[0][0].length !== 32)
            throw new Error("TLV 0 should be 32 bytes");
          return {
            type: "nprofile",
            data: {
              pubkey: utils$1.bytesToHex(tlv[0][0]),
              relays: tlv[1] ? tlv[1].map((d) => utf8Decoder.decode(d)) : []
            }
          };
        }
        case "nevent": {
          let tlv = parseTLV(data);
          if (!tlv[0]?.[0])
            throw new Error("missing TLV 0 for nevent");
          if (tlv[0][0].length !== 32)
            throw new Error("TLV 0 should be 32 bytes");
          if (tlv[2] && tlv[2][0].length !== 32)
            throw new Error("TLV 2 should be 32 bytes");
          return {
            type: "nevent",
            data: {
              id: utils$1.bytesToHex(tlv[0][0]),
              relays: tlv[1] ? tlv[1].map((d) => utf8Decoder.decode(d)) : [],
              author: tlv[2]?.[0] ? utils$1.bytesToHex(tlv[2][0]) : void 0
            }
          };
        }
        case "naddr": {
          let tlv = parseTLV(data);
          if (!tlv[0]?.[0])
            throw new Error("missing TLV 0 for naddr");
          if (!tlv[2]?.[0])
            throw new Error("missing TLV 2 for naddr");
          if (tlv[2][0].length !== 32)
            throw new Error("TLV 2 should be 32 bytes");
          if (!tlv[3]?.[0])
            throw new Error("missing TLV 3 for naddr");
          if (tlv[3][0].length !== 4)
            throw new Error("TLV 3 should be 4 bytes");
          return {
            type: "naddr",
            data: {
              identifier: utf8Decoder.decode(tlv[0][0]),
              pubkey: utils$1.bytesToHex(tlv[2][0]),
              kind: parseInt(utils$1.bytesToHex(tlv[3][0]), 16),
              relays: tlv[1] ? tlv[1].map((d) => utf8Decoder.decode(d)) : []
            }
          };
        }
        case "nrelay": {
          let tlv = parseTLV(data);
          if (!tlv[0]?.[0])
            throw new Error("missing TLV 0 for nrelay");
          return {
            type: "nrelay",
            data: utf8Decoder.decode(tlv[0][0])
          };
        }
        case "nsec":
        case "npub":
        case "note":
          return { type: prefix, data: utils$1.bytesToHex(data) };
        default:
          throw new Error(`unknown prefix ${prefix}`);
      }
    }
    function parseTLV(data) {
      let result = {};
      let rest = data;
      while (rest.length > 0) {
        let t = rest[0];
        let l = rest[1];
        let v = rest.slice(2, 2 + l);
        rest = rest.slice(2 + l);
        if (v.length < l)
          continue;
        result[t] = result[t] || [];
        result[t].push(v);
      }
      return result;
    }
    function nsecEncode(hex) {
      return encodeBytes("nsec", hex);
    }
    function npubEncode(hex) {
      return encodeBytes("npub", hex);
    }
    function noteEncode(hex) {
      return encodeBytes("note", hex);
    }
    function encodeBytes(prefix, hex) {
      let data = utils$1.hexToBytes(hex);
      let words = bech32.toWords(data);
      return bech32.encode(prefix, words, Bech32MaxSize);
    }
    function nprofileEncode(profile) {
      let data = encodeTLV({
        0: [utils$1.hexToBytes(profile.pubkey)],
        1: (profile.relays || []).map((url) => utf8Encoder$1.encode(url))
      });
      let words = bech32.toWords(data);
      return bech32.encode("nprofile", words, Bech32MaxSize);
    }
    function neventEncode(event) {
      let data = encodeTLV({
        0: [utils$1.hexToBytes(event.id)],
        1: (event.relays || []).map((url) => utf8Encoder$1.encode(url)),
        2: event.author ? [utils$1.hexToBytes(event.author)] : []
      });
      let words = bech32.toWords(data);
      return bech32.encode("nevent", words, Bech32MaxSize);
    }
    function naddrEncode(addr) {
      let kind = new ArrayBuffer(4);
      new DataView(kind).setUint32(0, addr.kind, false);
      let data = encodeTLV({
        0: [utf8Encoder$1.encode(addr.identifier)],
        1: (addr.relays || []).map((url) => utf8Encoder$1.encode(url)),
        2: [utils$1.hexToBytes(addr.pubkey)],
        3: [new Uint8Array(kind)]
      });
      let words = bech32.toWords(data);
      return bech32.encode("naddr", words, Bech32MaxSize);
    }
    function nrelayEncode(url) {
      let data = encodeTLV({
        0: [utf8Encoder$1.encode(url)]
      });
      let words = bech32.toWords(data);
      return bech32.encode("nrelay", words, Bech32MaxSize);
    }
    function encodeTLV(tlv) {
      let entries = [];
      Object.entries(tlv).forEach(([t, vs]) => {
        vs.forEach((v) => {
          let entry = new Uint8Array(v.length + 2);
          entry.set([parseInt(t)], 0);
          entry.set([v.length], 1);
          entry.set(v, 2);
          entries.push(entry);
        });
      });
      return utils$1.concatBytes(...entries);
    }

    // nip04.ts
    var nip04_exports = {};
    __export(nip04_exports, {
      decrypt: () => decrypt,
      encrypt: () => encrypt
    });
    async function encrypt(privkey, pubkey, text) {
      const key = getSharedSecret(privkey, "02" + pubkey);
      const normalizedKey = getNormalizedX(key);
      let iv = Uint8Array.from(randomBytes(16));
      let plaintext = utf8Encoder$1.encode(text);
      let cryptoKey = await crypto.subtle.importKey(
        "raw",
        normalizedKey,
        { name: "AES-CBC" },
        false,
        ["encrypt"]
      );
      let ciphertext = await crypto.subtle.encrypt(
        { name: "AES-CBC", iv },
        cryptoKey,
        plaintext
      );
      let ctb64 = base64.encode(new Uint8Array(ciphertext));
      let ivb64 = base64.encode(new Uint8Array(iv.buffer));
      return `${ctb64}?iv=${ivb64}`;
    }
    async function decrypt(privkey, pubkey, data) {
      let [ctb64, ivb64] = data.split("?iv=");
      let key = getSharedSecret(privkey, "02" + pubkey);
      let normalizedKey = getNormalizedX(key);
      let cryptoKey = await crypto.subtle.importKey(
        "raw",
        normalizedKey,
        { name: "AES-CBC" },
        false,
        ["decrypt"]
      );
      let ciphertext = base64.decode(ctb64);
      let iv = base64.decode(ivb64);
      let plaintext = await crypto.subtle.decrypt(
        { name: "AES-CBC", iv },
        cryptoKey,
        ciphertext
      );
      let text = utf8Decoder.decode(plaintext);
      return text;
    }
    function getNormalizedX(key) {
      return key.slice(1, 33);
    }

    // nip05.ts
    var nip05_exports = {};
    __export(nip05_exports, {
      queryProfile: () => queryProfile,
      searchDomain: () => searchDomain,
      useFetchImplementation: () => useFetchImplementation
    });
    var _fetch;
    try {
      _fetch = fetch;
    } catch {
    }
    function useFetchImplementation(fetchImplementation) {
      _fetch = fetchImplementation;
    }
    async function searchDomain(domain, query = "") {
      try {
        let res = await (await _fetch(`https://${domain}/.well-known/nostr.json?name=${query}`)).json();
        return res.names;
      } catch (_) {
        return {};
      }
    }
    async function queryProfile(fullname) {
      let [name, domain] = fullname.split("@");
      if (!domain) {
        domain = name;
        name = "_";
      }
      if (!name.match(/^[A-Za-z0-9-_.]+$/))
        return null;
      if (!domain.includes("."))
        return null;
      let res;
      try {
        res = await (await _fetch(`https://${domain}/.well-known/nostr.json?name=${name}`)).json();
      } catch (err) {
        return null;
      }
      if (!res?.names?.[name])
        return null;
      let pubkey = res.names[name];
      let relays = res.relays?.[pubkey] || [];
      return {
        pubkey,
        relays
      };
    }

    // nip06.ts
    var nip06_exports = {};
    __export(nip06_exports, {
      generateSeedWords: () => generateSeedWords,
      privateKeyFromSeedWords: () => privateKeyFromSeedWords,
      validateWords: () => validateWords
    });
    function privateKeyFromSeedWords(mnemonic, passphrase) {
      let root = HDKey.fromMasterSeed(mnemonicToSeedSync_1(mnemonic, passphrase));
      let privateKey = root.derive(`m/44'/1237'/0'/0/0`).privateKey;
      if (!privateKey)
        throw new Error("could not derive private key");
      return utils$1.bytesToHex(privateKey);
    }
    function generateSeedWords() {
      return generateMnemonic_1(wordlist);
    }
    function validateWords(words) {
      return validateMnemonic_1(words, wordlist);
    }

    // nip10.ts
    var nip10_exports = {};
    __export(nip10_exports, {
      parse: () => parse
    });
    function parse(event) {
      const result = {
        reply: void 0,
        root: void 0,
        mentions: [],
        profiles: []
      };
      const eTags = [];
      for (const tag of event.tags) {
        if (tag[0] === "e" && tag[1]) {
          eTags.push(tag);
        }
        if (tag[0] === "p" && tag[1]) {
          result.profiles.push({
            pubkey: tag[1],
            relays: tag[2] ? [tag[2]] : []
          });
        }
      }
      for (let eTagIndex = 0; eTagIndex < eTags.length; eTagIndex++) {
        const eTag = eTags[eTagIndex];
        const [_, eTagEventId, eTagRelayUrl, eTagMarker] = eTag;
        const eventPointer = {
          id: eTagEventId,
          relays: eTagRelayUrl ? [eTagRelayUrl] : []
        };
        const isFirstETag = eTagIndex === 0;
        const isLastETag = eTagIndex === eTags.length - 1;
        if (eTagMarker === "root") {
          result.root = eventPointer;
          continue;
        }
        if (eTagMarker === "reply") {
          result.reply = eventPointer;
          continue;
        }
        if (eTagMarker === "mention") {
          result.mentions.push(eventPointer);
          continue;
        }
        if (isFirstETag) {
          result.root = eventPointer;
          continue;
        }
        if (isLastETag) {
          result.reply = eventPointer;
          continue;
        }
        result.mentions.push(eventPointer);
      }
      return result;
    }

    // nip13.ts
    var nip13_exports = {};
    __export(nip13_exports, {
      getPow: () => getPow
    });
    function getPow(id) {
      return getLeadingZeroBits(utils$1.hexToBytes(id));
    }
    function getLeadingZeroBits(hash) {
      let total, i, bits;
      for (i = 0, total = 0; i < hash.length; i++) {
        bits = msb(hash[i]);
        total += bits;
        if (bits !== 8) {
          break;
        }
      }
      return total;
    }
    function msb(b) {
      let n = 0;
      if (b === 0) {
        return 8;
      }
      while (b >>= 1) {
        n++;
      }
      return 7 - n;
    }

    // nip21.ts
    var nip21_exports = {};
    __export(nip21_exports, {
      BECH32_REGEX: () => BECH32_REGEX,
      NOSTR_URI_REGEX: () => NOSTR_URI_REGEX,
      parse: () => parse2,
      test: () => test
    });
    var BECH32_REGEX = /[\x21-\x7E]{1,83}1[023456789acdefghjklmnpqrstuvwxyz]{6,}/;
    var NOSTR_URI_REGEX = new RegExp(`nostr:(${BECH32_REGEX.source})`);
    function test(value) {
      return typeof value === "string" && new RegExp(`^${NOSTR_URI_REGEX.source}$`).test(value);
    }
    function parse2(uri) {
      const match = uri.match(new RegExp(`^${NOSTR_URI_REGEX.source}$`));
      if (!match)
        throw new Error(`Invalid Nostr URI: ${uri}`);
      return {
        uri: match[0],
        value: match[1],
        decoded: decode(match[1])
      };
    }

    // nip26.ts
    var nip26_exports = {};
    __export(nip26_exports, {
      createDelegation: () => createDelegation,
      getDelegator: () => getDelegator
    });
    function createDelegation(privateKey, parameters) {
      let conditions = [];
      if ((parameters.kind || -1) >= 0)
        conditions.push(`kind=${parameters.kind}`);
      if (parameters.until)
        conditions.push(`created_at<${parameters.until}`);
      if (parameters.since)
        conditions.push(`created_at>${parameters.since}`);
      let cond = conditions.join("&");
      if (cond === "")
        throw new Error("refusing to create a delegation without any conditions");
      let sighash = sha256$3(
        utf8Encoder$1.encode(`nostr:delegation:${parameters.pubkey}:${cond}`)
      );
      let sig = utils$1.bytesToHex(
        schnorr.signSync(sighash, privateKey)
      );
      return {
        from: getPublicKey(privateKey),
        to: parameters.pubkey,
        cond,
        sig
      };
    }
    function getDelegator(event) {
      let tag = event.tags.find((tag2) => tag2[0] === "delegation" && tag2.length >= 4);
      if (!tag)
        return null;
      let pubkey = tag[1];
      let cond = tag[2];
      let sig = tag[3];
      let conditions = cond.split("&");
      for (let i = 0; i < conditions.length; i++) {
        let [key, operator, value] = conditions[i].split(/\b/);
        if (key === "kind" && operator === "=" && event.kind === parseInt(value))
          continue;
        else if (key === "created_at" && operator === "<" && event.created_at < parseInt(value))
          continue;
        else if (key === "created_at" && operator === ">" && event.created_at > parseInt(value))
          continue;
        else
          return null;
      }
      let sighash = sha256$3(
        utf8Encoder$1.encode(`nostr:delegation:${event.pubkey}:${cond}`)
      );
      if (!schnorr.verifySync(sig, sighash, pubkey))
        return null;
      return pubkey;
    }

    // nip27.ts
    var nip27_exports = {};
    __export(nip27_exports, {
      matchAll: () => matchAll,
      regex: () => regex,
      replaceAll: () => replaceAll
    });
    var regex = () => new RegExp(`\\b${NOSTR_URI_REGEX.source}\\b`, "g");
    function* matchAll(content) {
      const matches = content.matchAll(regex());
      for (const match of matches) {
        const [uri, value] = match;
        yield {
          uri,
          value,
          decoded: decode(value),
          start: match.index,
          end: match.index + uri.length
        };
      }
    }
    function replaceAll(content, replacer) {
      return content.replaceAll(regex(), (uri, value) => {
        return replacer({
          uri,
          value,
          decoded: decode(value)
        });
      });
    }

    // nip39.ts
    var nip39_exports = {};
    __export(nip39_exports, {
      useFetchImplementation: () => useFetchImplementation2,
      validateGithub: () => validateGithub
    });
    var _fetch2;
    try {
      _fetch2 = fetch;
    } catch {
    }
    function useFetchImplementation2(fetchImplementation) {
      _fetch2 = fetchImplementation;
    }
    async function validateGithub(pubkey, username, proof) {
      try {
        let res = await (await _fetch2(`https://gist.github.com/${username}/${proof}/raw`)).text();
        return res === `Verifying that I control the following Nostr public key: ${pubkey}`;
      } catch (_) {
        return false;
      }
    }

    // nip42.ts
    var nip42_exports = {};
    __export(nip42_exports, {
      authenticate: () => authenticate
    });
    var authenticate = async ({
      challenge,
      relay,
      sign
    }) => {
      const e = {
        kind: 22242 /* ClientAuth */,
        created_at: Math.floor(Date.now() / 1e3),
        tags: [
          ["relay", relay.url],
          ["challenge", challenge]
        ],
        content: ""
      };
      const pub = relay.auth(await sign(e));
      return new Promise((resolve, reject) => {
        pub.on("ok", function ok() {
          pub.off("ok", ok);
          resolve();
        });
        pub.on("failed", function fail(reason) {
          pub.off("failed", fail);
          reject(reason);
        });
      });
    };

    // nip57.ts
    var nip57_exports = {};
    __export(nip57_exports, {
      getZapEndpoint: () => getZapEndpoint,
      makeZapReceipt: () => makeZapReceipt,
      makeZapRequest: () => makeZapRequest,
      useFetchImplementation: () => useFetchImplementation3,
      validateZapRequest: () => validateZapRequest
    });
    var _fetch3;
    try {
      _fetch3 = fetch;
    } catch {
    }
    function useFetchImplementation3(fetchImplementation) {
      _fetch3 = fetchImplementation;
    }
    async function getZapEndpoint(metadata) {
      try {
        let lnurl = "";
        let { lud06, lud16 } = JSON.parse(metadata.content);
        if (lud06) {
          let { words } = bech32.decode(lud06, 1e3);
          let data = bech32.fromWords(words);
          lnurl = utf8Decoder.decode(data);
        } else if (lud16) {
          let [name, domain] = lud16.split("@");
          lnurl = `https://${domain}/.well-known/lnurlp/${name}`;
        } else {
          return null;
        }
        let res = await _fetch3(lnurl);
        let body = await res.json();
        if (body.allowsNostr && body.nostrPubkey) {
          return body.callback;
        }
      } catch (err) {
      }
      return null;
    }
    function makeZapRequest({
      profile,
      event,
      amount,
      relays,
      comment = ""
    }) {
      if (!amount)
        throw new Error("amount not given");
      if (!profile)
        throw new Error("profile not given");
      let zr = {
        kind: 9734,
        created_at: Math.round(Date.now() / 1e3),
        content: comment,
        tags: [
          ["p", profile],
          ["amount", amount.toString()],
          ["relays", ...relays]
        ]
      };
      if (event) {
        zr.tags.push(["e", event]);
      }
      return zr;
    }
    function validateZapRequest(zapRequestString) {
      let zapRequest;
      try {
        zapRequest = JSON.parse(zapRequestString);
      } catch (err) {
        return "Invalid zap request JSON.";
      }
      if (!validateEvent(zapRequest))
        return "Zap request is not a valid Nostr event.";
      if (!verifySignature(zapRequest))
        return "Invalid signature on zap request.";
      let p = zapRequest.tags.find(([t, v]) => t === "p" && v);
      if (!p)
        return "Zap request doesn't have a 'p' tag.";
      if (!p[1].match(/^[a-f0-9]{64}$/))
        return "Zap request 'p' tag is not valid hex.";
      let e = zapRequest.tags.find(([t, v]) => t === "e" && v);
      if (e && !e[1].match(/^[a-f0-9]{64}$/))
        return "Zap request 'e' tag is not valid hex.";
      let relays = zapRequest.tags.find(([t, v]) => t === "relays" && v);
      if (!relays)
        return "Zap request doesn't have a 'relays' tag.";
      return null;
    }
    function makeZapReceipt({
      zapRequest,
      preimage,
      bolt11,
      paidAt
    }) {
      let zr = JSON.parse(zapRequest);
      let tagsFromZapRequest = zr.tags.filter(
        ([t]) => t === "e" || t === "p" || t === "a"
      );
      let zap = {
        kind: 9735,
        created_at: Math.round(paidAt.getTime() / 1e3),
        content: "",
        tags: [
          ...tagsFromZapRequest,
          ["bolt11", bolt11],
          ["description", zapRequest]
        ]
      };
      if (preimage) {
        zap.tags.push(["preimage", preimage]);
      }
      return zap;
    }
    utils$1.hmacSha256Sync = (key, ...msgs) => hmac(sha256$3, key, utils$1.concatBytes(...msgs));
    utils$1.sha256Sync = (...msgs) => sha256$3(utils$1.concatBytes(...msgs));

    function number(n) {
        if (!Number.isSafeInteger(n) || n < 0)
            throw new Error(`Wrong positive integer: ${n}`);
    }
    function bool(b) {
        if (typeof b !== 'boolean')
            throw new Error(`Expected boolean, not ${b}`);
    }
    function bytes(b, ...lengths) {
        if (!(b instanceof Uint8Array))
            throw new TypeError('Expected Uint8Array');
        if (lengths.length > 0 && !lengths.includes(b.length))
            throw new TypeError(`Expected Uint8Array of length ${lengths}, not of length=${b.length}`);
    }
    function hash(hash) {
        if (typeof hash !== 'function' || typeof hash.create !== 'function')
            throw new Error('Hash should be wrapped by utils.wrapConstructor');
        number(hash.outputLen);
        number(hash.blockLen);
    }
    function exists(instance, checkFinished = true) {
        if (instance.destroyed)
            throw new Error('Hash instance has been destroyed');
        if (checkFinished && instance.finished)
            throw new Error('Hash#digest() has already been called');
    }
    function output(out, instance) {
        bytes(out);
        const min = instance.outputLen;
        if (out.length < min) {
            throw new Error(`digestInto() expects output buffer of length at least ${min}`);
        }
    }
    const assert$1 = {
        number,
        bool,
        bytes,
        hash,
        exists,
        output,
    };

    /*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) */
    // We use `globalThis.crypto`, but node.js versions earlier than v19 don't
    // declare it in global scope. For node.js, package.json#exports field mapping
    // rewrites import from `crypto` to `cryptoNode`, which imports native module.
    // Makes the utils un-importable in browsers without a bundler.
    // Once node.js 18 is deprecated, we can just drop the import.
    // Cast array to view
    const createView = (arr) => new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
    // The rotate right (circular right shift) operation for uint32
    const rotr = (word, shift) => (word << (32 - shift)) | (word >>> shift);
    // big-endian hardware is rare. Just in case someone still decides to run hashes:
    // early-throw an error because we don't support BE yet.
    const isLE = new Uint8Array(new Uint32Array([0x11223344]).buffer)[0] === 0x44;
    if (!isLE)
        throw new Error('Non little-endian hardware is not supported');
    const hexes = Array.from({ length: 256 }, (v, i) => i.toString(16).padStart(2, '0'));
    /**
     * @example bytesToHex(Uint8Array.from([0xde, 0xad, 0xbe, 0xef])) // 'deadbeef'
     */
    function bytesToHex(uint8a) {
        // pre-caching improves the speed 6x
        if (!(uint8a instanceof Uint8Array))
            throw new Error('Uint8Array expected');
        let hex = '';
        for (let i = 0; i < uint8a.length; i++) {
            hex += hexes[uint8a[i]];
        }
        return hex;
    }
    function utf8ToBytes(str) {
        if (typeof str !== 'string') {
            throw new TypeError(`utf8ToBytes expected string, got ${typeof str}`);
        }
        return new TextEncoder().encode(str);
    }
    function toBytes(data) {
        if (typeof data === 'string')
            data = utf8ToBytes(data);
        if (!(data instanceof Uint8Array))
            throw new TypeError(`Expected input type is Uint8Array (got ${typeof data})`);
        return data;
    }
    // For runtime check if class implements interface
    class Hash {
        // Safe version that clones internal state
        clone() {
            return this._cloneInto();
        }
    }
    function wrapConstructor(hashConstructor) {
        const hashC = (message) => hashConstructor().update(toBytes(message)).digest();
        const tmp = hashConstructor();
        hashC.outputLen = tmp.outputLen;
        hashC.blockLen = tmp.blockLen;
        hashC.create = () => hashConstructor();
        return hashC;
    }

    // Polyfill for Safari 14
    function setBigUint64(view, byteOffset, value, isLE) {
        if (typeof view.setBigUint64 === 'function')
            return view.setBigUint64(byteOffset, value, isLE);
        const _32n = BigInt(32);
        const _u32_max = BigInt(0xffffffff);
        const wh = Number((value >> _32n) & _u32_max);
        const wl = Number(value & _u32_max);
        const h = isLE ? 4 : 0;
        const l = isLE ? 0 : 4;
        view.setUint32(byteOffset + h, wh, isLE);
        view.setUint32(byteOffset + l, wl, isLE);
    }
    // Base SHA2 class (RFC 6234)
    class SHA2 extends Hash {
        constructor(blockLen, outputLen, padOffset, isLE) {
            super();
            this.blockLen = blockLen;
            this.outputLen = outputLen;
            this.padOffset = padOffset;
            this.isLE = isLE;
            this.finished = false;
            this.length = 0;
            this.pos = 0;
            this.destroyed = false;
            this.buffer = new Uint8Array(blockLen);
            this.view = createView(this.buffer);
        }
        update(data) {
            assert$1.exists(this);
            const { view, buffer, blockLen } = this;
            data = toBytes(data);
            const len = data.length;
            for (let pos = 0; pos < len;) {
                const take = Math.min(blockLen - this.pos, len - pos);
                // Fast path: we have at least one block in input, cast it to view and process
                if (take === blockLen) {
                    const dataView = createView(data);
                    for (; blockLen <= len - pos; pos += blockLen)
                        this.process(dataView, pos);
                    continue;
                }
                buffer.set(data.subarray(pos, pos + take), this.pos);
                this.pos += take;
                pos += take;
                if (this.pos === blockLen) {
                    this.process(view, 0);
                    this.pos = 0;
                }
            }
            this.length += data.length;
            this.roundClean();
            return this;
        }
        digestInto(out) {
            assert$1.exists(this);
            assert$1.output(out, this);
            this.finished = true;
            // Padding
            // We can avoid allocation of buffer for padding completely if it
            // was previously not allocated here. But it won't change performance.
            const { buffer, view, blockLen, isLE } = this;
            let { pos } = this;
            // append the bit '1' to the message
            buffer[pos++] = 0b10000000;
            this.buffer.subarray(pos).fill(0);
            // we have less than padOffset left in buffer, so we cannot put length in current block, need process it and pad again
            if (this.padOffset > blockLen - pos) {
                this.process(view, 0);
                pos = 0;
            }
            // Pad until full block byte with zeros
            for (let i = pos; i < blockLen; i++)
                buffer[i] = 0;
            // Note: sha512 requires length to be 128bit integer, but length in JS will overflow before that
            // You need to write around 2 exabytes (u64_max / 8 / (1024**6)) for this to happen.
            // So we just write lowest 64 bits of that value.
            setBigUint64(view, blockLen - 8, BigInt(this.length * 8), isLE);
            this.process(view, 0);
            const oview = createView(out);
            const len = this.outputLen;
            // NOTE: we do division by 4 later, which should be fused in single op with modulo by JIT
            if (len % 4)
                throw new Error('_sha2: outputLen should be aligned to 32bit');
            const outLen = len / 4;
            const state = this.get();
            if (outLen > state.length)
                throw new Error('_sha2: outputLen bigger than state');
            for (let i = 0; i < outLen; i++)
                oview.setUint32(4 * i, state[i], isLE);
        }
        digest() {
            const { buffer, outputLen } = this;
            this.digestInto(buffer);
            const res = buffer.slice(0, outputLen);
            this.destroy();
            return res;
        }
        _cloneInto(to) {
            to || (to = new this.constructor());
            to.set(...this.get());
            const { blockLen, buffer, length, finished, destroyed, pos } = this;
            to.length = length;
            to.pos = pos;
            to.finished = finished;
            to.destroyed = destroyed;
            if (length % blockLen)
                to.buffer.set(buffer);
            return to;
        }
    }

    // Choice: a ? b : c
    const Chi = (a, b, c) => (a & b) ^ (~a & c);
    // Majority function, true if any two inpust is true
    const Maj = (a, b, c) => (a & b) ^ (a & c) ^ (b & c);
    // Round constants:
    // first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311)
    // prettier-ignore
    const SHA256_K = new Uint32Array([
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]);
    // Initial state (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
    // prettier-ignore
    const IV = new Uint32Array([
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]);
    // Temporary buffer, not used to store anything between runs
    // Named this way because it matches specification.
    const SHA256_W = new Uint32Array(64);
    class SHA256 extends SHA2 {
        constructor() {
            super(64, 32, 8, false);
            // We cannot use array here since array allows indexing by variable
            // which means optimizer/compiler cannot use registers.
            this.A = IV[0] | 0;
            this.B = IV[1] | 0;
            this.C = IV[2] | 0;
            this.D = IV[3] | 0;
            this.E = IV[4] | 0;
            this.F = IV[5] | 0;
            this.G = IV[6] | 0;
            this.H = IV[7] | 0;
        }
        get() {
            const { A, B, C, D, E, F, G, H } = this;
            return [A, B, C, D, E, F, G, H];
        }
        // prettier-ignore
        set(A, B, C, D, E, F, G, H) {
            this.A = A | 0;
            this.B = B | 0;
            this.C = C | 0;
            this.D = D | 0;
            this.E = E | 0;
            this.F = F | 0;
            this.G = G | 0;
            this.H = H | 0;
        }
        process(view, offset) {
            // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array
            for (let i = 0; i < 16; i++, offset += 4)
                SHA256_W[i] = view.getUint32(offset, false);
            for (let i = 16; i < 64; i++) {
                const W15 = SHA256_W[i - 15];
                const W2 = SHA256_W[i - 2];
                const s0 = rotr(W15, 7) ^ rotr(W15, 18) ^ (W15 >>> 3);
                const s1 = rotr(W2, 17) ^ rotr(W2, 19) ^ (W2 >>> 10);
                SHA256_W[i] = (s1 + SHA256_W[i - 7] + s0 + SHA256_W[i - 16]) | 0;
            }
            // Compression function main loop, 64 rounds
            let { A, B, C, D, E, F, G, H } = this;
            for (let i = 0; i < 64; i++) {
                const sigma1 = rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25);
                const T1 = (H + sigma1 + Chi(E, F, G) + SHA256_K[i] + SHA256_W[i]) | 0;
                const sigma0 = rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22);
                const T2 = (sigma0 + Maj(A, B, C)) | 0;
                H = G;
                G = F;
                F = E;
                E = (D + T1) | 0;
                D = C;
                C = B;
                B = A;
                A = (T1 + T2) | 0;
            }
            // Add the compressed chunk to the current hash value
            A = (A + this.A) | 0;
            B = (B + this.B) | 0;
            C = (C + this.C) | 0;
            D = (D + this.D) | 0;
            E = (E + this.E) | 0;
            F = (F + this.F) | 0;
            G = (G + this.G) | 0;
            H = (H + this.H) | 0;
            this.set(A, B, C, D, E, F, G, H);
        }
        roundClean() {
            SHA256_W.fill(0);
        }
        destroy() {
            this.set(0, 0, 0, 0, 0, 0, 0, 0);
            this.buffer.fill(0);
        }
    }
    // Constants from https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
    class SHA224 extends SHA256 {
        constructor() {
            super();
            this.A = 0xc1059ed8 | 0;
            this.B = 0x367cd507 | 0;
            this.C = 0x3070dd17 | 0;
            this.D = 0xf70e5939 | 0;
            this.E = 0xffc00b31 | 0;
            this.F = 0x68581511 | 0;
            this.G = 0x64f98fa7 | 0;
            this.H = 0xbefa4fa4 | 0;
            this.outputLen = 28;
        }
    }
    /**
     * SHA2-256 hash function
     * @param message - data that would be hashed
     */
    const sha256 = wrapConstructor(() => new SHA256());
    wrapConstructor(() => new SHA224());

    const utf8Encoder = new TextEncoder();
    function assert(ok, msg) {
        if (!ok)
            throw Error(msg);
    }
    const DEFAULT_RELAYS = [
        'wss://relay.damus.io/',
        'wss://relay.nostr.bg/',
        'wss://nostr.fmt.wiz.biz/',
        'wss://relay.nostr.band/',
        'wss://nos.lol/'
    ];
    class NostrEscrow {
        relays;
        pool;
        constructor() {
            this.relays = DEFAULT_RELAYS;
            this.pool = new SimplePool();
        }
        async setRelays(relays) {
            this.relays = relays;
            await Promise.all(relays.map((url) => {
                this.pool.ensureRelay(url);
            }));
        }
        async getContract(role, nsec, event_id) {
            const { type, data } = nip19_exports.decode(nsec);
            assert(type == "nsec", "invalid nsec");
            const priv = data;
            const sub = await this.pool.get(this.relays, { ids: [event_id] });
            if (!sub)
                throw Error("unknown contract");
            const taker_tag = sub.tags.find((el) => {
                return el[0] == "p";
            });
            if (!taker_tag)
                throw Error("taker pub unknown");
            const taker_pub = taker_tag[1];
            const maker_pub = sub.pubkey;
            const taker_reply = await this.pool.get(this.relays, { "#e": [event_id], authors: [taker_pub] });
            let plain;
            let plain_reply = null;
            if (role == "taker") {
                console.log("TAKER!!!!", priv, maker_pub, sub.content);
                plain = await nip04_exports.decrypt(priv, maker_pub, sub.content);
                if (taker_reply)
                    plain_reply = await nip04_exports.decrypt(priv, maker_pub, taker_reply.content);
            }
            else if (role == "maker") {
                plain = await nip04_exports.decrypt(priv, taker_pub, sub.content);
                if (taker_reply)
                    plain_reply = await nip04_exports.decrypt(priv, taker_pub, taker_reply.content);
            }
            else {
                throw Error("only maker or taker can view the original contract");
            }
            const [ver, escrow_pub, maker_sats, taker_sats, escrow_sats, contract_text, maker_sig,] = JSON.parse(plain);
            assert(ver == 0, "invalid contract ");
            let taker_sig = null;
            if (plain_reply) {
                const [ver, sig,] = JSON.parse(plain_reply);
                assert(ver == 0, "invalid contract ");
                taker_sig = sig;
            }
            return {
                maker_pub: maker_pub,
                taker_pub: taker_pub,
                escrow_pub: escrow_pub,
                maker_sats: maker_sats,
                taker_sats: taker_sats,
                escrow_sats: escrow_sats,
                contract_text: contract_text,
                maker_sig: maker_sig,
                taker_sig: taker_sig
            };
        }
        async publishAndWait(ev) {
            const sub = this.pool.publish(this.relays, ev);
            return new Promise((res) => {
                sub.on("ok", () => {
                    res(ev);
                });
            });
        }
        async createContract(contract) {
            const ev = await this.createContractEvent(contract);
            return await this.publishAndWait(ev);
        }
        async acceptContract(contract) {
            const ev = await this.createAcceptEvent(contract);
            return await this.publishAndWait(ev);
        }
        async createAcceptEvent(params) {
            const [taker_priv, taker_pub] = this.getPrivPub(params.taker_nsec);
            const ev = {
                kind: 3333,
                tags: [
                    ["e", params.event_id],
                ],
                content: await nip04_exports.encrypt(taker_priv, params.maker_pub, JSON.stringify([0, params.taker_sig])),
            };
            return this.signEvent(ev, taker_pub, taker_priv);
        }
        async createContractEvent(params) {
            const [maker_priv, maker_pub] = this.getPrivPub(params.maker_nsec);
            const subcontract = {
                escrow_pub: params.escrow_pub,
                maker_sats: params.maker_sats,
                taker_sats: params.taker_sats,
                escrow_sats: params.escrow_sats,
                contract_text: params.contract_text,
                maker_sig: params.maker_sig,
            };
            const subcontract_serial = JSON.stringify([
                0,
                subcontract.escrow_pub,
                subcontract.maker_sats,
                subcontract.taker_sats,
                subcontract.escrow_sats,
                subcontract.contract_text,
                subcontract.maker_sig,
            ]);
            const subcontract_hash = bytesToHex(sha256(utf8Encoder.encode(subcontract_serial)));
            const ev = {
                kind: 3333,
                tags: [
                    ["p", params.taker_pub],
                    ["hash", subcontract_hash],
                ],
                content: await nip04_exports.encrypt(maker_priv, params.taker_pub, subcontract_serial),
            };
            return this.signEvent(ev, maker_pub, maker_priv);
        }
        signEvent(ev, pub, priv) {
            const created_at = Math.floor(Date.now() / 1000);
            const tmp = { ...ev, created_at: created_at, pubkey: pub };
            const ret = {
                ...tmp,
                id: getEventHash(tmp),
                sig: signEvent(tmp, priv),
            };
            return ret;
        }
        getPrivPub(nsec) {
            const { type, data } = nip19_exports.decode(nsec);
            assert(type == "nsec", "invalid nsec");
            const priv = data;
            const pub = getPublicKey(priv);
            return [priv, pub];
        }
    }

    exports.NostrEscrow = NostrEscrow;

}));
//# sourceMappingURL=index.js.map
