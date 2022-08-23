require('mocha');

const { requireBox } = require('@liquidapps/box-utils');
const { assert } = require('chai'); // Using Assert style
const { getCreateAccount } = requireBox('seed-eos/tools/eos/utils');

const artifacts = requireBox('seed-eos/tools/eos/artifacts');
const deployer = requireBox('seed-eos/tools/eos/deployer');
const { getEosWrapper } = requireBox('seed-eos/tools/eos/eos-wrapper');

const contractCode = 'oracle';
const ctrt = artifacts.require(`./${contractCode}/`);
const { eosio } = requireBox('test-extensions/lib/index');
let deployedContract;

const fs = require('fs');
const inputJson = JSON.parse(fs.readFileSync('./sample/sample_output.json', 'utf-8'));
const {decodeAndVerify} = require('../api/decode');

const produceData = (input, rogueMessage = false, rogueSignature = false) => {
    const messages = input.messages.map(el => {
        return rogueMessage ? 'hehe' + el.substring(2) : el.substring(2)
    });
    const signatures = [];
    for(const i in input.signatures) {
        const cleaned = input.signatures[i].substring(2).substring(0,128) + input.signatures[i].substring(input.signatures[i].length-2);
        const r = cleaned.substring(0,64);
        const s = cleaned.substring(64,128);
        const v = cleaned.substring(128);
        // r,s,v -> v,r,s
        signatures.push(`${v}${r}${s}${rogueSignature ? 'hehe' : ''}`);
    }
    return {messages, signatures};
}

const crypto = require('crypto');
const fetch = require('node-fetch');
const env = require('dotenv').config();

const { API_KEY, API_SECRET, API_PASSPHRASE } = env.parsed;
if (!API_KEY || !API_SECRET || !API_PASSPHRASE) {
  console.log('error: missing one or more of API_KEY, API_SECRET, API_PASSPHRASE environment variables');
  process.exit(1)
}

const API_URL = 'https://api.exchange.coinbase.com'

async function returnNewData() {
  const timestamp = (new Date().getTime() / 1000).toString();
  const message = timestamp + 'GET' + '/oracle';
  const hmac = crypto.createHmac('sha256', Buffer.from(API_SECRET, 'base64')).update(message);
  const signature = hmac.digest('base64')
  
  const headers = {
    'CB-ACCESS-SIGN': signature,
    'CB-ACCESS-TIMESTAMP': timestamp,
    'CB-ACCESS-KEY': API_KEY,
    'CB-ACCESS-PASSPHRASE': API_PASSPHRASE
  }
  
  const res = await fetch(API_URL + '/oracle', { method: 'GET', headers });
  return await res.json();
}

describe(`${contractCode} Contract`, () => {
    const code = 'oracle';
    let tableHelper;
    before(done => {
        (async () => {
            try {
                tableHelper = await deployer.deploy(ctrt, code);
                const keys = await getCreateAccount(code);
                const eosTestAcc = getEosWrapper({
                  keyProvider: keys.active.privateKey,
                  httpEndpoint: 'http://localhost:8888'
                });
                deployedContract = await eosTestAcc.contract(code);
                done();
            }
            catch (e) {
                done(e);
            }
        })();
    });

    /*
        ensure price data is updated
    */

    /*
        check(timestamp > current_time_point().sec_since_epoch() - (60 * 60), "data > 60m old");
    */

    it('test old data', done => {
        (async () => {
            try {
                const {messages, signatures} = produceData(inputJson)
                const res = await deployedContract.update({
                    messages,
                    signatures
                }, {
                    authorization: `${code}@active`,
                    broadcast: true,
                    sign: true
                });
                assert(res.processed.action_traces[0].console,"BTCETHXTZDAIREPZRXBATKNCLINKCOMPUNIGRTSNX");
                done();
            }
            catch (e) {
                if(e && e.error && e.error.details && e.error.details[1]) {
                    console.log(e.error.details[1].message);
                } 
                done(e);
            }
        })();
    });

    /*
        check(message.size() == 512, "msg length != 512");
    */

    it('test bad message size', done => {
        (async () => {
            try {
                try {
                    const {messages, signatures} = produceData(inputJson,true)
                    await deployedContract.update({
                        messages,
                        signatures
                    }, {
                      authorization: `${code}@active`,
                      broadcast: true,
                      sign: true
                    });
                } catch(e) {
                    assert(e.details[0].message,"assertion failure with message: msg length != 512");
                    failed = true;
                }
                assert(failed,"should have failed");
                done();
            }
            catch (e) {
                if(e && e.error && e.error.details && e.error.details[1]) {
                    console.log(e.error.details[1].message);
                } 
                done(e);
            }
        })();
    });

    /*
        check(signature.size() == 130, "sig length != 130");
    */

    it('test bad signature size', done => {
        (async () => {
            try {
                try {
                    const {messages, signatures} = produceData(inputJson,false,true)
                    await deployedContract.update({
                        messages,
                        signatures
                    }, {
                      authorization: `${code}@active`,
                      broadcast: true,
                      sign: true
                    });
                } catch(e) {
                    assert(e.details[0].message,"assertion failure with message: sig length != 130");
                    failed = true;
                }
                assert(failed,"should have failed");
                done();
            }
            catch (e) {
                if(e && e.error && e.error.details && e.error.details[1]) {
                    console.log(e.error.details[1].message);
                } 
                done(e);
            }
        })();
    });

    it('test update', done => {
        (async () => {
            try {
                const newData = await returnNewData();
                const deserializedData = await decodeAndVerify(newData);
                const {messages, signatures} = produceData(newData)
                await deployedContract.update({
                    messages,
                    signatures
                }, {
                    authorization: `${code}@active`,
                    broadcast: true,
                    sign: true
                });

                for(const el of deserializedData) {
                    const res = await tableHelper.eos.getTableRows({
                        code: code,
                        scope: code,
                        table: el[2].toLowerCase(),
                        json: true
                    });
                    if(res.rows[0]){
                        const row = res.rows[0].data;
                        if(Number(el[1]) > Math.floor(+new Date() / 1000) - (60*60)){
                            assert(Number(el[1]),row.timestamp);
                            assert(Number(el[3]),row.price);
                        } else {
                            assert(false,"data older than 60m");
                        }
                    }
                }
                done();
            }
            catch (e) {
                if(e && e.error && e.error.details && e.error.details[1]) {
                    console.log(e.error.details[1].message);
                } 
                done(e);
            }
        })();
    });

    /*
        ToDo...
        check(message.timestamp > current.data.timestamp, "old data");
        check(type == api_type, "wrong type");
        check(recovered_uncompressed == 0, "failed recover uncompressed");
        check(to_hex(ret.data(),ret.size()) == uncompressed_key, "key mismatch");
    */
});