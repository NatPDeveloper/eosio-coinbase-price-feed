const Web3 = require('web3');

const data = "0x00000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000062f9360400000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000005a720ef700000000000000000000000000000000000000000000000000000000000000006707269636573000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000034254430000000000000000000000000000000000000000000000000000000000";
const desiredOutput = "0x4b5fcf9a2851b6df0cdc4e178aeef373fb86131b3bf7bed9531aa75536a0f49a";

// https://github.com/cryptocoinjs/keccak/blob/e77962484b20fe3c1ca3ddd7e3f455bb118cc545/lib/api/index.js#L12
// case 'keccak256': return new Keccak(1088, 512, null, 256, options)
const createKeccakHash = require("keccak");

// https://github.com/ethereumjs/ethereumjs-monorepo/blob/f5a1d773855f5624fb4664bb56bb71e292135e43/packages/util/src/internal.ts#L203
function isHexString(value, length) {
    if (typeof value !== 'string' || !value.match(/^0x[0-9A-Fa-f]*$/)) return false
  
    if (length && value.length !== 2 + 2 * length) return false
  
    return true
}

// https://github.com/ethereumjs/ethereumjs-monorepo/blob/f5a1d773855f5624fb4664bb56bb71e292135e43/packages/util/src/internal.ts#L56
/*

    - if length of hex is not even, add a 0 prefix

*/
function padToEven(value) {
    let a = value
  
    if (typeof a !== 'string') {
      throw new Error(`[padToEven] value must be type 'string', received ${typeof a}`)
    }
  
    if (a.length % 2) a = `0${a}`
  
    console.log(`padToEven: \n${a}`);
    return a
}

// https://github.com/ethereumjs/ethereumjs-monorepo/blob/f5a1d773855f5624fb4664bb56bb71e292135e43/packages/util/src/internal.ts#L31
/*

    - check if string prefixed with '0x'

*/
function isHexPrefixed(str) {
    if (typeof str !== 'string') {
      throw new Error(`[isHexPrefixed] input must be type 'string', received type ${typeof str}`)
    }
  
    console.log(`isHexPrefixed: \n${str[0] === '0' && str[1] === 'x'}`);
    return str[0] === '0' && str[1] === 'x'
}

// https://github.com/ethereumjs/ethereumjs-monorepo/blob/f5a1d773855f5624fb4664bb56bb71e292135e43/packages/util/src/internal.ts#L44
/*

    - remove 0x from prefix

*/
const stripHexPrefix = (str) => {
    if (typeof str !== 'string')
      throw new Error(`[stripHexPrefix] input must be type 'string', received ${typeof str}`)
  
    const res = isHexPrefixed(str) ? str.slice(2) : str
    console.log(`stripHexPrefix: \n${res}`);
    return res
}

// https://github.com/ethereumjs/ethereumjs-monorepo/blob/f5a1d773855f5624fb4664bb56bb71e292135e43/packages/util/src/bytes.ts#L154
/*

    - check if val is buffer or string
        - if buffer, buffer from buffer
        - if is string and is hex format, pad, strip and buffer as hex

*/
const toBuffer = function (v) {
    if (Buffer.isBuffer(v)) {
      console.log(`toBuffer isBuffer: \n${Buffer.from(v)}`);
      return Buffer.from(v)
    }
  
    if (typeof v === 'string') {
      if (!isHexString(v)) {
        throw new Error(
          `Cannot convert string to buffer. toBuffer only supports 0x-prefixed hex strings and this string was given: ${v}`
        )
      }
      const res = Buffer.from(padToEven(stripHexPrefix(v)), 'hex')
      console.log(`toBuffer string: \n${res}`);
      return res;
    }
}

// https://github.com/ChainSafe/web3.js/blob/5a437ce5b7985e919a8dceb8eab76d496f1232b6/packages/web3-utils/src/utils.js#L373
/*

    - check if string is in hex format [0-9a-f]

*/
var isHexStrict = function (hex) {
    console.log(`isHexStrict: \n${(typeof hex === 'string' || typeof hex === 'number') && /^(-)?0x[0-9a-f]*$/i.test(hex)}`)
    return ((typeof hex === 'string' || typeof hex === 'number') && /^(-)?0x[0-9a-f]*$/i.test(hex));
};

// https://github.com/ethereumjs/ethereumjs-monorepo/blob/f5a1d773855f5624fb4664bb56bb71e292135e43/packages/util/src/bytes.ts#L205
const bufferToHex = function (buf) {
    buf = toBuffer(buf)
    const res = '0x' + buf.toString('hex')
    console.log(`bufferToHex: \n${res}`)
    return res
}

// ethereum-cryptography/src/hash-utils.ts
function createHashFunction(hashConstructor) {
  return msg => {
    const hash = hashConstructor();
    hash.update(msg);
    const res = Buffer.from(hash.digest());
    console.log(`createHashFunction: \n${res}`);
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
    console.log(`keccak256: \n${res}`);
    return res;
}

const sha3 = value => {
    // https://github.com/ChainSafe/web3.js/blob/5a437ce5b7985e919a8dceb8eab76d496f1232b6/packages/web3-utils/src/index.js#L387
    // https://github.com/ChainSafe/web3.js/blob/5a437ce5b7985e919a8dceb8eab76d496f1232b6/packages/web3-utils/src/utils.js#L494
    if (isHexStrict(value) && /^0x/i.test((value).toString())) {
        value = toBuffer(value);
    }

    // https://github.com/ChainSafe/web3.js/blob/5a437ce5b7985e919a8dceb8eab76d496f1232b6/packages/web3-utils/src/utils.js#L497
    // https://github.com/ethereumjs/ethereumjs-monorepo/blob/f5a1d773855f5624fb4664bb56bb71e292135e43/packages/devp2p/src/util.ts#L13
    return bufferToHex(keccak256(value));
}

(() => {
    const web3 = new Web3();
    console.log('web3 calculated hash',web3.utils.keccak256(data),web3.utils.keccak256(data) === desiredOutput);
    console.log('web3 calculated sha3',web3.utils.sha3(data));

    console.log(`self-calculated hash: ${sha3(data)}`)
})()