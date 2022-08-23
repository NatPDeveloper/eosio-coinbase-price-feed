/*

    Credit: https://github.com/barnabee/coinbase-oracle-verify

*/

const crypto = require('crypto');
const fetch = require('node-fetch');
const {decodeAndVerify} = require('./decode');
const env = require('dotenv').config();

const { API_KEY, API_SECRET, API_PASSPHRASE } = env.parsed;
if (!API_KEY || !API_SECRET || !API_PASSPHRASE) {
  console.log('error: missing one or more of API_KEY, API_SECRET, API_PASSPHRASE environment variables');
  process.exit(1)
}

const API_URL = 'https://api.exchange.coinbase.com'

async function main() {
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
  const json = await res.json();
  decodeAndVerify(json);
}

main();