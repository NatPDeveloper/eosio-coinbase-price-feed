/*

    Credit: https://github.com/barnabee/coinbase-oracle-verify

*/

const Web3 = require('web3');
const fs = require('fs');

async function decodeAndVerify (data) {
	const { messages, signatures } = data;
	const returnData = [];
	
	const web3 = new Web3()
	for (let i=0; i<messages.length; ++i) {

		// Decode the data — this works just fine and we get extremely reasonable looking data
		record = Object.values(web3.eth.abi.decodeParameters(['string', 'uint', 'string', 'uint'], messages[i])).slice(0, -1);

		// Attempt to recover the signer, if this is 0xfCEAdAFab14d46e20144F48824d0C09B1a03F2BC we think it's "good"
		adr = web3.eth.accounts.recover(web3.utils.keccak256(messages[i]), signatures[i], false); 
	
		// console.log(`js sig: ${signatures[i]}`)
		// console.log(`js dig: ${web3.utils.keccak256(messages[i])}`)
		
		// Print what we found...
		// console.log(record, adr === '0xfCEAdAFab14d46e20144F48824d0C09B1a03F2BC' ? 'signature OK' : 'BAD signature!');
		// console.log('hash',web3.utils.keccak256(messages[i]))
		if(adr !== '0xfCEAdAFab14d46e20144F48824d0C09B1a03F2BC') {
			throw new Error('signature does not match');
		}
		returnData.push(record);
	}
	
	return returnData;
}


// // Decide and verify the signature from standard input (expect JSON in Coinbase Oracle API format)
// const inputJson = JSON.parse(fs.readFileSync('./sample/sample_output.json', 'utf-8'))
// decodeAndVerify(inputJson);

module.exports = {decodeAndVerify}