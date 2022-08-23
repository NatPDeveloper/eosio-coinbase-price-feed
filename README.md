# eosio-coinbase-price-feed
EOSIO contract for verifying and updating coinbase's signed price oracle feed

**This is a proof of concept contract.**

Big thank you to `@ElMato` and `@matt_witherspoon` for their help.

# Getting Started

This contract uses the `zeus-sdk` framework. To get started with zeus visit the LiquidApps docs [here](https://docs.liquidapps.io/liquidapps-documentation/working-with-zeus-sdk/overview).

**Prereqs:**

- nodejs 16
- curl, cmake, make, git
- maybe some others I'm forgetting

**Commands:**

```bash
git clone https://github.com/NatPDeveloper/eosio-coinbase-price-feed
cd eosio-coinbase-price-feed

# get on the zeus train, it's actually pretty nice
npm i -g @liquidapps/zeus-cmd

# install zeus and npm dependencies
zeus unbox

# run full eosio testnet with crypto feature enabled and compile contract
zeus test -c --enable-features

# kill services
zeus start-localenv --kill
```

**.env file**

Be sure to create a `.env.` file with the provided `.sample.env` file provided to query the coinbase api.

```bash
API_PASSPHRASE= # first thing you get
API_SECRET= # then you get this
API_KEY= # this is the api key after you create that you can click and copy
```

# Contract Overview

- [ACTION `update`](#action-update)
- [TABLE `btc`](#table-btc) (available for tokens BTC ETH XTZ DAI REP ZRX BAT KNC LINK COMP UNI GRT SNX by lowercase singleton name)

## ACTION `update`

> Update oracle price feed. Logic is such that the provider does not need to worry if the price is stale, the contract will not update if the data is > 60m old or not newer than previously stored data.

### params

- `{vector<string>} messages` - signed message data, details below
- `{vector<string>} signatures` - signature, details below

## TABLE `btc`

> Singletons available for each token by lower case name. The reason for this is so that a contract can specify exactly which prices it wishes to read instead of all of them.

```cpp
struct data_t {
    uint64_t timestamp;
    uint64_t price;
};

TABLE btc {
    data_t data;
};
typedef singleton<"btc"_n, btc> btc_t;
```

### params

- `{data_t} data` - timestamp and price for symbol

### example

```bash
cleos get table oracle oracle btc
{
  "rows": [{
      "data": {
        "timestamp": 1661260860,
        "price": "21389520000"
      }
    }
  ],
  "more": false,
  "next_key": ""
}
```

# Background

Coinbase is the only exchange I'm aware of that actually signs its price data and makes it freely available by API. This costs them nothing in terms of on chain resources and allows anyone to provide that data to a blockchain where it can be validated on chain.

Coinbase currently offers this [price API](https://docs.cloud.coinbase.com/exchange/reference/exchangerestapi_getcoinbasepriceoracle) for 13 tokens. BTC ETH XTZ DAI REP ZRX BAT KNC LINK COMP UNI GRT SNX. DAI (July 13), BAT (July 13), and REP (Aug 14) are not up to date. Because of this I would not recommend relying too heavily on any of those prices.

Coinbase's public key is `0xfCEAdAFab14d46e20144F48824d0C09B1a03F2BC`. The uncompressed format is `044170a2083dccbc2be253885a8d0e9f7ce859eb370d0c5cae3b6994af4cb9d6663e1c135774a355e78570fc76579402a6657b58c4a1ccc73237c7244297a48cfb`. You can read more on key formats [here](https://github.com/bitcoinbook/bitcoinbook/blob/develop/ch04.asciidoc#public-key-formats).

I looked to [Compound's open oracle price feed](https://github.com/compound-finance/open-oracle) for help with signature formatting and assertion checks. This contract also accepts this signed price data and allows the registering of additional trusted API providers.

AntelopIO recently added some crypto functions to its smart contract developer kit. Namely the `keccak` hash and `k1_recover` functions which can be used to produce an uncompressed ETH key to validate a blockchain trx.

# Example Data

The returned data from coinbase looks like this (there's 13 entries, but we'll just look at BTC for now):

<details>
<summary>Example Data</summary>

```json
{
    "timestamp": "1660499460",
    "messages": [
        "0x00000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000062f9360400000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000005a720ef700000000000000000000000000000000000000000000000000000000000000006707269636573000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000034254430000000000000000000000000000000000000000000000000000000000"
    ],
    "signatures": [
        "0xaf834758a351608e8ba3acb4ec835d9e9bb92a4e5d3586a5ad8eee7282da458941272b9ab0ae97d6a0bbec7db4e6af345b46d45d9d608dbf26d0b3929d63eab8000000000000000000000000000000000000000000000000000000000000001c"
    ],
    "prices": {
        "BTC": "24278.79"
    }
}
```
</details>

# Message Format

The message is 512 characters (not including 0x) in length. The encoded types are `string`, `uint`, `string`, and `uint` matching `api_type`, `timestamp`, `symbol`, `price`, e.g. `[ 'prices', '1660499460', 'BTC', '24278790000' ]`. Strings are little endian and uints are big endian. Let's break down the message.

<details>
<summary>Message Format</summary>

```json
0x - leading hex symbol -> more reading https://stackoverflow.com/questions/2670639/why-are-hexadecimal-numbers-prefixed-with-0x

// timestamp
0000000000000000000000000000000000000000000000000000000000000080
0000000000000000000000000000000000000000000000000000000062f93604

// 62f93604 base16 to base 10 conversion -> 1660499460 https://www.unitconverters.net/numbers/base-16-to-base-10.htm

// price
00000000000000000000000000000000000000000000000000000000000000c0
00000000000000000000000000000000000000000000000000000005a720ef70

// 05a720ef70 base16 to base 10 conversion -> 24278790000 https://www.unitconverters.net/numbers/base-16-to-base-10.htm

// api type
0000000000000000000000000000000000000000000000000000000000000006
7072696365730000000000000000000000000000000000000000000000000000

// 707269636573 hex to string -> prices https://codebeautify.org/hex-string-converter

// symbol
0000000000000000000000000000000000000000000000000000000000000003
4254430000000000000000000000000000000000000000000000000000000000

// 425443 hex to string -> BTC https://codebeautify.org/hex-string-converter
```
</details>

# Signature Format

Signature is 192 characters in length (not counting leading 0x). This is in r,s,v format and we need it in v,r,s. v must be 1 byte, r and s must be 32 bytes totaling 65 bytes or 130 hex characters (hex is 2 char per byte). More reading on vrs [here](https://ethereum.stackexchange.com/questions/2256/ethereum-ecrecover-signature-verification-and-encryption/2257#2257).

<details>
<summary>Signature Format</summary>

```json
0x - leading hex symbol -> more reading https://stackoverflow.com/questions/2670639/why-are-hexadecimal-numbers-prefixed-with-0x

// r
af834758a351608e8ba3acb4ec835d9e9bb92a4e5d3586a5ad8eee7282da4589

// s
41272b9ab0ae97d6a0bbec7db4e6af345b46d45d9d608dbf26d0b3929d63eab8

// v
000000000000000000000000000000000000000000000000000000000000001c

// re ordered

// v 1c to base 10 is 28
1c

// r
af834758a351608e8ba3acb4ec835d9e9bb92a4e5d3586a5ad8eee7282da4589

// s
41272b9ab0ae97d6a0bbec7db4e6af345b46d45d9d608dbf26d0b3929d63eab8
```
</details>

# Crypto Functions

Let's talk about [`keccak`](https://github.com/AntelopeIO/cdt/blob/main/libraries/eosiolib/crypto.cpp#L96) and [`k1_recover`](https://github.com/AntelopeIO/fc/blob/b39f636b41b32bcea48d00953900bf9c9998e409/src/crypto/k1_recover.cpp#L13). `keccak` is a [`sha3`](https://en.wikipedia.org/wiki/SHA-3) hash and ETH keys using the [`secp256k1`](https://en.bitcoin.it/wiki/Secp256k1) curve. `k1_recover` produces an uncompressed key and returns 0 if successful in recovering the key.

`keccak` takes a character array of hex and the length and produces a hash.


```
eosio::checksum256 keccak(const char* data, uint32_t length)

keccak(chars,sizeof(chars))
```

`k1_recover` takes a 65 byte signature, 65 byte digest and the key recovered will be 65 bytes. From the below you can see we take the hash of the message, convert that checksum to a hex string then hash the preamble as a hex string plus that message and pass the signature.

The preamble is `"\x19Ethereum Signed Message:\n32"` with the 32 representing the amount of bytes of the message's digest hash. Signatures must be 65 bytes, digests must be 32 bytes, and the returned key will always be 65 bytes

```cpp
checksum256 message_hash = hash(message);
string message_hash_string = hex_to_string(message_hash);

validate_signature(hash(preamble_hex + message_hash_string),signature);
```

# Additional Resources

There is an `/api` folder that has some proofs in it that I used to understand the js side of keccak, recover, and abi decoding that may be useful.