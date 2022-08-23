const data = "0x00000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000062f9360400000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000005a720ef700000000000000000000000000000000000000000000000000000000000000006707269636573000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000034254430000000000000000000000000000000000000000000000000000000000";
const desiredOutput = "0x4b5fcf9a2851b6df0cdc4e178aeef373fb86131b3bf7bed9531aa75536a0f49a";
const signature = "0xaf834758a351608e8ba3acb4ec835d9e9bb92a4e5d3586a5ad8eee7282da458941272b9ab0ae97d6a0bbec7db4e6af345b46d45d9d608dbf26d0b3929d63eab8000000000000000000000000000000000000000000000000000000000000001c"
const address = "0xfCEAdAFab14d46e20144F48824d0C09B1a03F2BC";

const createKeccakHash = require("keccak");
const elliptic = require("elliptic");
const Web3 = require('web3');
const secp256k1 = new elliptic.ec("secp256k1"); 

var isHexStrict = function (hex) {
    // console.log(`isHexStrict: \n${(typeof hex === 'string' || typeof hex === 'number') && /^(-)?0x[0-9a-f]*$/i.test(hex)}`)
    return ((typeof hex === 'string' || typeof hex === 'number') && /^(-)?0x[0-9a-f]*$/i.test(hex));
};

var hexToBytes = function(hex) {
    hex = hex.toString(16);

    if (!isHexStrict(hex)) {
        throw new Error('Given value "'+ hex +'" is not a valid hex string.');
    }

    hex = hex.replace(/^0x/i,'');

    for (var bytes = [], c = 0; c < hex.length; c += 2)
        bytes.push(parseInt(hex.substr(c, 2), 16));
    return bytes;
};

var utf8ToHex = function(str) {
    str = utf8.encode(str);
    var hex = "";

    // remove \u0000 padding from either side
    str = str.replace(/^(?:\u0000)*/,'');
    str = str.split("").reverse().join("");
    str = str.replace(/^(?:\u0000)*/,'');
    str = str.split("").reverse().join("");

    for(var i = 0; i < str.length; i++) {
        var code = str.charCodeAt(i);
        // if (code !== 0) {
        var n = code.toString(16);
        hex += n.length < 2 ? '0' + n : n;
        // }
    }

    return "0x" + hex;
};

function isHexString(value, length) {
    if (typeof value !== 'string' || !value.match(/^0x[0-9A-Fa-f]*$/)) return false
  
    if (length && value.length !== 2 + 2 * length) return false
  
    return true
}

function padToEven(value) {
    let a = value
  
    if (typeof a !== 'string') {
      throw new Error(`[padToEven] value must be type 'string', received ${typeof a}`)
    }
  
    if (a.length % 2) a = `0${a}`
  
    // console.log(`padToEven: \n${a}`);
    return a
}

function isHexPrefixed(str) {
    if (typeof str !== 'string') {
      throw new Error(`[isHexPrefixed] input must be type 'string', received type ${typeof str}`)
    }
  
    // console.log(`isHexPrefixed: \n${str[0] === '0' && str[1] === 'x'}`);
    return str[0] === '0' && str[1] === 'x'
}

const stripHexPrefix = (str) => {
    if (typeof str !== 'string')
      throw new Error(`[stripHexPrefix] input must be type 'string', received ${typeof str}`)
  
    const res = isHexPrefixed(str) ? str.slice(2) : str
    // console.log(`stripHexPrefix: \n${res}`);
    return res
}

const toBuffer = function (v) {
    if (Buffer.isBuffer(v)) {
    //   console.log(`toBuffer isBuffer: \n${Buffer.from(v)}`);
      return Buffer.from(v)
    }
  
    if (typeof v === 'string') {
      if (!isHexString(v)) {
        throw new Error(
          `Cannot convert string to buffer. toBuffer only supports 0x-prefixed hex strings and this string was given: ${v}`
        )
      }
      const res = Buffer.from(padToEven(stripHexPrefix(v)), 'hex')
    //   console.log(`toBuffer string: \n${res}`);
      return res;
    }
}

// https://github.com/ethereumjs/ethereumjs-monorepo/blob/f5a1d773855f5624fb4664bb56bb71e292135e43/packages/util/src/bytes.ts#L205
const bufferToHex = function (buf) {
    buf = toBuffer(buf)
    const res = '0x' + buf.toString('hex')
    // console.log(`bufferToHex: \n${res}`)
    return res
}

// ethereum-cryptography/src/hash-utils.ts
function createHashFunction(hashConstructor) {
  return msg => {
    const hash = hashConstructor();
    hash.update(msg);
    const res = Buffer.from(hash.digest());
    // console.log(`createHashFunction: \n${res}`);
    return res;
  };
}

// ethereum-cryptography/src/keccak.ts
const _keccak256 = createHashFunction(() =>
  createKeccakHash("keccak256")
);

// https://github.com/ethereumjs/ethereumjs-monorepo/blob/f5a1d773855f5624fb4664bb56bb71e292135e43/packages/devp2p/src/util.ts#L13
function keccak256(...buffers) {
    const buffer = Buffer.concat(buffers)
    const res = Buffer.from(_keccak256(buffer))
    // console.log(`keccak256: \n${res}`);
    return res;
}


function hashMessage(data) {
    console.log(`data`,data);
    var messageHex = isHexStrict(data) ? data : utf8ToHex(data);
    var messageBytes = hexToBytes(messageHex);
    console.log(`messageHex`,messageHex);
    var messageBuffer = Buffer.from(messageBytes);
    var preamble = '\x19Ethereum Signed Message:\n' + messageBytes.length;
    console.log(`messageBytes.length`,messageBytes.length);
    console.log(`preamble`,preamble);
    var preambleBuffer = Buffer.from(preamble);
    var ethMessage = Buffer.concat([preambleBuffer, messageBuffer]);
    return bufferToHex(keccak256(ethMessage));
};

const sha3 = value => {
    if (isHexStrict(value) && /^0x/i.test((value).toString())) {
        value = toBuffer(value);
    }

    return bufferToHex(keccak256(value));
}

const length = a => (a.length - 2) / 2;

const slice = (i, j, bs) => "0x" + bs.slice(i * 2 + 2, j * 2 + 2);

const decodeSignature = hex => [slice(64, length(hex), hex), slice(0, 32, hex), slice(32, 64, hex)];

const toNumber = hex => parseInt(hex.slice(2), 16);

const SHIFT = [0, 8, 16, 24];

const KECCAK_PADDING = [1, 256, 65536, 16777216];

const RC = [1, 0, 32898, 0, 32906, 2147483648, 2147516416, 2147483648, 32907, 0, 2147483649, 0, 2147516545, 2147483648, 32777, 2147483648, 138, 0, 136, 0, 2147516425, 0, 2147483658, 0, 2147516555, 0, 139, 2147483648, 32905, 2147483648, 32771, 2147483648, 32770, 2147483648, 128, 2147483648, 32778, 0, 2147483658, 2147483648, 2147516545, 2147483648, 32896, 2147483648, 2147483649, 0, 2147516424, 2147483648];

const HEX_CHARS = '0123456789abcdef'.split('');

const f = s => {
    var h, l, n, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15, b16, b17, b18, b19, b20, b21, b22, b23, b24, b25, b26, b27, b28, b29, b30, b31, b32, b33, b34, b35, b36, b37, b38, b39, b40, b41, b42, b43, b44, b45, b46, b47, b48, b49;
  
    for (n = 0; n < 48; n += 2) {
      c0 = s[0] ^ s[10] ^ s[20] ^ s[30] ^ s[40];
      c1 = s[1] ^ s[11] ^ s[21] ^ s[31] ^ s[41];
      c2 = s[2] ^ s[12] ^ s[22] ^ s[32] ^ s[42];
      c3 = s[3] ^ s[13] ^ s[23] ^ s[33] ^ s[43];
      c4 = s[4] ^ s[14] ^ s[24] ^ s[34] ^ s[44];
      c5 = s[5] ^ s[15] ^ s[25] ^ s[35] ^ s[45];
      c6 = s[6] ^ s[16] ^ s[26] ^ s[36] ^ s[46];
      c7 = s[7] ^ s[17] ^ s[27] ^ s[37] ^ s[47];
      c8 = s[8] ^ s[18] ^ s[28] ^ s[38] ^ s[48];
      c9 = s[9] ^ s[19] ^ s[29] ^ s[39] ^ s[49];
  
      h = c8 ^ (c2 << 1 | c3 >>> 31);
      l = c9 ^ (c3 << 1 | c2 >>> 31);
      s[0] ^= h;
      s[1] ^= l;
      s[10] ^= h;
      s[11] ^= l;
      s[20] ^= h;
      s[21] ^= l;
      s[30] ^= h;
      s[31] ^= l;
      s[40] ^= h;
      s[41] ^= l;
      h = c0 ^ (c4 << 1 | c5 >>> 31);
      l = c1 ^ (c5 << 1 | c4 >>> 31);
      s[2] ^= h;
      s[3] ^= l;
      s[12] ^= h;
      s[13] ^= l;
      s[22] ^= h;
      s[23] ^= l;
      s[32] ^= h;
      s[33] ^= l;
      s[42] ^= h;
      s[43] ^= l;
      h = c2 ^ (c6 << 1 | c7 >>> 31);
      l = c3 ^ (c7 << 1 | c6 >>> 31);
      s[4] ^= h;
      s[5] ^= l;
      s[14] ^= h;
      s[15] ^= l;
      s[24] ^= h;
      s[25] ^= l;
      s[34] ^= h;
      s[35] ^= l;
      s[44] ^= h;
      s[45] ^= l;
      h = c4 ^ (c8 << 1 | c9 >>> 31);
      l = c5 ^ (c9 << 1 | c8 >>> 31);
      s[6] ^= h;
      s[7] ^= l;
      s[16] ^= h;
      s[17] ^= l;
      s[26] ^= h;
      s[27] ^= l;
      s[36] ^= h;
      s[37] ^= l;
      s[46] ^= h;
      s[47] ^= l;
      h = c6 ^ (c0 << 1 | c1 >>> 31);
      l = c7 ^ (c1 << 1 | c0 >>> 31);
      s[8] ^= h;
      s[9] ^= l;
      s[18] ^= h;
      s[19] ^= l;
      s[28] ^= h;
      s[29] ^= l;
      s[38] ^= h;
      s[39] ^= l;
      s[48] ^= h;
      s[49] ^= l;
  
      b0 = s[0];
      b1 = s[1];
      b32 = s[11] << 4 | s[10] >>> 28;
      b33 = s[10] << 4 | s[11] >>> 28;
      b14 = s[20] << 3 | s[21] >>> 29;
      b15 = s[21] << 3 | s[20] >>> 29;
      b46 = s[31] << 9 | s[30] >>> 23;
      b47 = s[30] << 9 | s[31] >>> 23;
      b28 = s[40] << 18 | s[41] >>> 14;
      b29 = s[41] << 18 | s[40] >>> 14;
      b20 = s[2] << 1 | s[3] >>> 31;
      b21 = s[3] << 1 | s[2] >>> 31;
      b2 = s[13] << 12 | s[12] >>> 20;
      b3 = s[12] << 12 | s[13] >>> 20;
      b34 = s[22] << 10 | s[23] >>> 22;
      b35 = s[23] << 10 | s[22] >>> 22;
      b16 = s[33] << 13 | s[32] >>> 19;
      b17 = s[32] << 13 | s[33] >>> 19;
      b48 = s[42] << 2 | s[43] >>> 30;
      b49 = s[43] << 2 | s[42] >>> 30;
      b40 = s[5] << 30 | s[4] >>> 2;
      b41 = s[4] << 30 | s[5] >>> 2;
      b22 = s[14] << 6 | s[15] >>> 26;
      b23 = s[15] << 6 | s[14] >>> 26;
      b4 = s[25] << 11 | s[24] >>> 21;
      b5 = s[24] << 11 | s[25] >>> 21;
      b36 = s[34] << 15 | s[35] >>> 17;
      b37 = s[35] << 15 | s[34] >>> 17;
      b18 = s[45] << 29 | s[44] >>> 3;
      b19 = s[44] << 29 | s[45] >>> 3;
      b10 = s[6] << 28 | s[7] >>> 4;
      b11 = s[7] << 28 | s[6] >>> 4;
      b42 = s[17] << 23 | s[16] >>> 9;
      b43 = s[16] << 23 | s[17] >>> 9;
      b24 = s[26] << 25 | s[27] >>> 7;
      b25 = s[27] << 25 | s[26] >>> 7;
      b6 = s[36] << 21 | s[37] >>> 11;
      b7 = s[37] << 21 | s[36] >>> 11;
      b38 = s[47] << 24 | s[46] >>> 8;
      b39 = s[46] << 24 | s[47] >>> 8;
      b30 = s[8] << 27 | s[9] >>> 5;
      b31 = s[9] << 27 | s[8] >>> 5;
      b12 = s[18] << 20 | s[19] >>> 12;
      b13 = s[19] << 20 | s[18] >>> 12;
      b44 = s[29] << 7 | s[28] >>> 25;
      b45 = s[28] << 7 | s[29] >>> 25;
      b26 = s[38] << 8 | s[39] >>> 24;
      b27 = s[39] << 8 | s[38] >>> 24;
      b8 = s[48] << 14 | s[49] >>> 18;
      b9 = s[49] << 14 | s[48] >>> 18;
  
      s[0] = b0 ^ ~b2 & b4;
      s[1] = b1 ^ ~b3 & b5;
      s[10] = b10 ^ ~b12 & b14;
      s[11] = b11 ^ ~b13 & b15;
      s[20] = b20 ^ ~b22 & b24;
      s[21] = b21 ^ ~b23 & b25;
      s[30] = b30 ^ ~b32 & b34;
      s[31] = b31 ^ ~b33 & b35;
      s[40] = b40 ^ ~b42 & b44;
      s[41] = b41 ^ ~b43 & b45;
      s[2] = b2 ^ ~b4 & b6;
      s[3] = b3 ^ ~b5 & b7;
      s[12] = b12 ^ ~b14 & b16;
      s[13] = b13 ^ ~b15 & b17;
      s[22] = b22 ^ ~b24 & b26;
      s[23] = b23 ^ ~b25 & b27;
      s[32] = b32 ^ ~b34 & b36;
      s[33] = b33 ^ ~b35 & b37;
      s[42] = b42 ^ ~b44 & b46;
      s[43] = b43 ^ ~b45 & b47;
      s[4] = b4 ^ ~b6 & b8;
      s[5] = b5 ^ ~b7 & b9;
      s[14] = b14 ^ ~b16 & b18;
      s[15] = b15 ^ ~b17 & b19;
      s[24] = b24 ^ ~b26 & b28;
      s[25] = b25 ^ ~b27 & b29;
      s[34] = b34 ^ ~b36 & b38;
      s[35] = b35 ^ ~b37 & b39;
      s[44] = b44 ^ ~b46 & b48;
      s[45] = b45 ^ ~b47 & b49;
      s[6] = b6 ^ ~b8 & b0;
      s[7] = b7 ^ ~b9 & b1;
      s[16] = b16 ^ ~b18 & b10;
      s[17] = b17 ^ ~b19 & b11;
      s[26] = b26 ^ ~b28 & b20;
      s[27] = b27 ^ ~b29 & b21;
      s[36] = b36 ^ ~b38 & b30;
      s[37] = b37 ^ ~b39 & b31;
      s[46] = b46 ^ ~b48 & b40;
      s[47] = b47 ^ ~b49 & b41;
      s[8] = b8 ^ ~b0 & b2;
      s[9] = b9 ^ ~b1 & b3;
      s[18] = b18 ^ ~b10 & b12;
      s[19] = b19 ^ ~b11 & b13;
      s[28] = b28 ^ ~b20 & b22;
      s[29] = b29 ^ ~b21 & b23;
      s[38] = b38 ^ ~b30 & b32;
      s[39] = b39 ^ ~b31 & b33;
      s[48] = b48 ^ ~b40 & b42;
      s[49] = b49 ^ ~b41 & b43;
  
      s[0] ^= RC[n];
      s[1] ^= RC[n + 1];
    }
};

const update = (state, message) => {
    var length = message.length,
        blocks = state.blocks,
        byteCount = state.blockCount << 2,
        blockCount = state.blockCount,
        outputBlocks = state.outputBlocks,
        s = state.s,
        index = 0,
        i,
        code;
  
    // update
    while (index < length) {
      if (state.reset) {
        state.reset = false;
        blocks[0] = state.block;
        for (i = 1; i < blockCount + 1; ++i) {
          blocks[i] = 0;
        }
      }
      if (typeof message !== "string") {
        for (i = state.start; index < length && i < byteCount; ++index) {
          blocks[i >> 2] |= message[index] << SHIFT[i++ & 3];
        }
      } else {
        for (i = state.start; index < length && i < byteCount; ++index) {
          code = message.charCodeAt(index);
          if (code < 0x80) {
            blocks[i >> 2] |= code << SHIFT[i++ & 3];
          } else if (code < 0x800) {
            blocks[i >> 2] |= (0xc0 | code >> 6) << SHIFT[i++ & 3];
            blocks[i >> 2] |= (0x80 | code & 0x3f) << SHIFT[i++ & 3];
          } else if (code < 0xd800 || code >= 0xe000) {
            blocks[i >> 2] |= (0xe0 | code >> 12) << SHIFT[i++ & 3];
            blocks[i >> 2] |= (0x80 | code >> 6 & 0x3f) << SHIFT[i++ & 3];
            blocks[i >> 2] |= (0x80 | code & 0x3f) << SHIFT[i++ & 3];
          } else {
            code = 0x10000 + ((code & 0x3ff) << 10 | message.charCodeAt(++index) & 0x3ff);
            blocks[i >> 2] |= (0xf0 | code >> 18) << SHIFT[i++ & 3];
            blocks[i >> 2] |= (0x80 | code >> 12 & 0x3f) << SHIFT[i++ & 3];
            blocks[i >> 2] |= (0x80 | code >> 6 & 0x3f) << SHIFT[i++ & 3];
            blocks[i >> 2] |= (0x80 | code & 0x3f) << SHIFT[i++ & 3];
          }
        }
      }
      state.lastByteIndex = i;
      if (i >= byteCount) {
        state.start = i - byteCount;
        state.block = blocks[blockCount];
        for (i = 0; i < blockCount; ++i) {
          s[i] ^= blocks[i];
        }
        f(s);
        state.reset = true;
      } else {
        state.start = i;
      }
    }
  
    // finalize
    i = state.lastByteIndex;
    blocks[i >> 2] |= KECCAK_PADDING[i & 3];
    if (state.lastByteIndex === byteCount) {
      blocks[0] = blocks[blockCount];
      for (i = 1; i < blockCount + 1; ++i) {
        blocks[i] = 0;
      }
    }
    blocks[blockCount - 1] |= 0x80000000;
    for (i = 0; i < blockCount; ++i) {
      s[i] ^= blocks[i];
    }
    f(s);
  
    // toString
    var hex = '',
        i = 0,
        j = 0,
        block;
    while (j < outputBlocks) {
      for (i = 0; i < blockCount && j < outputBlocks; ++i, ++j) {
        block = s[i];
        hex += HEX_CHARS[block >> 4 & 0x0F] + HEX_CHARS[block & 0x0F] + HEX_CHARS[block >> 12 & 0x0F] + HEX_CHARS[block >> 8 & 0x0F] + HEX_CHARS[block >> 20 & 0x0F] + HEX_CHARS[block >> 16 & 0x0F] + HEX_CHARS[block >> 28 & 0x0F] + HEX_CHARS[block >> 24 & 0x0F];
      }
      if (j % blockCount === 0) {
        f(s);
        i = 0;
      }
    }
    return "0x" + hex;
};

const Keccak = bits => ({
    blocks: [],
    reset: true,
    block: 0,
    start: 0,
    blockCount: 1600 - (bits << 1) >> 5,
    outputBlocks: bits >> 5,
    s: (s => [].concat(s, s, s, s, s))([0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
});

const keccak = bits => str => {
    var msg;
    if (str.slice(0, 2) === "0x") {
      msg = [];
      for (var i = 2, l = str.length; i < l; i += 2) msg.push(parseInt(str.slice(i, i + 2), 16));
    } else {
      msg = str;
    }
    return update(Keccak(bits, bits), msg);
};

const toChecksum = address => {
    const keccak256s = keccak(256);
    const addressHash = keccak256s(address.slice(2));
    let checksumAddress = "0x";
    for (let i = 0; i < 40; i++) checksumAddress += parseInt(addressHash[i + 2], 16) > 7 ? address[i + 2].toUpperCase() : address[i + 2];
    return checksumAddress;
};

recoverPubKey = function(msg, signature, j, enc) {
    assert((3 & j) === j, 'The recovery param is more than two bits');
    signature = new Signature(signature, enc);
  
    var n = this.n;
    var e = new BN(msg);
    var r = signature.r;
    var s = signature.s;
  
    // A set LSB signifies that the y-coordinate is odd
    var isYOdd = j & 1;
    var isSecondKey = j >> 1;
    if (r.cmp(this.curve.p.umod(this.curve.n)) >= 0 && isSecondKey)
      throw new Error('Unable to find sencond key candinate');
  
    // 1.1. Let x = r + jn.
    if (isSecondKey)
      r = this.curve.pointFromX(r.add(this.curve.n), isYOdd);
    else
      r = this.curve.pointFromX(r, isYOdd);
  
    var rInv = signature.r.invm(n);
    var s1 = n.sub(e).mul(rInv).umod(n);
    var s2 = s.mul(rInv).umod(n);
  
    // 1.6.1 Compute Q = r^-1 (sR -  eG)
    //               Q = r^-1 (sR + -eG)
    return this.g.mulAdd(s1, r, s2);
  };

const _recover = (hash, signature) => {
    const vals = decodeSignature(signature);
    const vrs = { v: toNumber(vals[0]), r: vals[1].slice(2), s: vals[2].slice(2) };
    const ecPublicKey = secp256k1.recoverPubKey(new Buffer(hash.slice(2), "hex"), vrs, vrs.v < 2 ? vrs.v : 1 - vrs.v % 2); // because odd vals mean v=0... sadly that means v=0 means v=1... I hate that
    
    const publicKey = "0x" + ecPublicKey.encode("hex", false).slice(2);
    console.log('ecPublicKey.encode("hex", false)',ecPublicKey.encode("hex", false))
    const _keccak = keccak(256);
    const publicHash = _keccak(publicKey);
    console.log(`publicHash`,publicHash);
    const address = toChecksum("0x" + publicHash.slice(-40));
    console.log(`address`,address);
    return address;
  };

function recover(message, signature, preFixed) {
    if (!preFixed) {
        message = hashMessage(message);
    }

    return _recover(message, signature);
};

(() => {
    const web3 = new Web3();

    console.log(`self-calculated address: ${recover(sha3(data),signature,false)}`,sha3(data)==desiredOutput,recover(sha3(data),signature,false)===address);
    console.log('web3 calculated address:',web3.eth.accounts.recover(web3.utils.keccak256(data), signature, false));
})()