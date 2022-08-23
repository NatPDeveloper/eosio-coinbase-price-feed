var EthersAbiCoder = require('@ethersproject/abi').AbiCoder;
const fs = require('fs');

var ethersAbiCoder = new EthersAbiCoder(function (type, value) {
    if (type.match(/^u?int/) && !Array.isArray(value) && (!(!!value && typeof value === 'object') || value.constructor.name !== 'BN')) {
        return value.toString();
    }
    return value;
});

// result method
function Result() {
}

const isSimplifiedStructFormat = (type) => {
    return typeof type === 'object' && typeof type.components === 'undefined' && typeof type.name === 'undefined';
};

const mapStructNameAndType = (structName) => {
    var type = 'tuple';

    if (structName.indexOf('[]') > -1) {
        type = 'tuple[]';
        structName = structName.slice(0, -2);
    }

    return {type: type, name: structName};
};

const mapStructToCoderFormat = (struct) => {
    var components = [];
    Object.keys(struct).forEach(function (key) {
        if (typeof struct[key] === 'object') {
            components.push(
                Object.assign(
                    mapStructNameAndType(key),
                    {
                        components: mapStructToCoderFormat(struct[key])
                    }
                )
            );

            return;
        }

        components.push({
            name: key,
            type: struct[key]
        });
    });

    return components;
};

const mapTypes = (types) => {
    var mappedTypes = [];
    types.forEach(function (type) {
        // Remap `function` type params to bytes24 since Ethers does not
        // recognize former type. Solidity docs say `Function` is a bytes24
        // encoding the contract address followed by the function selector hash.
        if (typeof type === 'object' && type.type === 'function'){
            type = Object.assign({}, type, { type: "bytes24" });
        }
        if (isSimplifiedStructFormat(type)) {
            var structName = Object.keys(type)[0];
            mappedTypes.push(
                Object.assign(
                    mapStructNameAndType(structName),
                    {
                        components: mapStructToCoderFormat(type[structName])
                    }
                )
            );

            return;
        }

        mappedTypes.push(type);
    });

    return mappedTypes;
};

const decodeParameters = (outputs, bytes) => {
    return decodeParametersWith(outputs, bytes, false);
}

const decodeParametersWith = (outputs, bytes, loose) => {
    if (outputs.length > 0 && (!bytes || bytes === '0x' || bytes === '0X')) {
        throw new Error(
            'Returned values aren\'t valid, did it run Out of Gas? ' +
            'You might also see this error if you are not using the ' +
            'correct ABI for the contract you are retrieving data from, ' +
            'requesting data from a block number that does not exist, ' +
            'or querying a node which is not fully synced.'
        );
    }

    var res = ethersAbiCoder.decode(mapTypes(outputs), '0x' + bytes.replace(/0x/i, ''), loose);
    console.log(`res: ${res}`);
    var returnValue = new Result();
    returnValue.__length__ = 0;

    outputs.forEach(function (output, i) {
        var decodedValue = res[returnValue.__length__];

        const isStringObject = typeof output === 'object' && output.type && output.type === 'string';
        const isStringType = typeof output === 'string' && output === 'string';

        // only convert `0x` to null if it's not string value
        decodedValue = (decodedValue === '0x' && !isStringObject && !isStringType) ? null : decodedValue;

        returnValue[i] = decodedValue;

        if ((typeof output === 'function' || !!output && typeof output === 'object') && output.name) {
            returnValue[output.name] = decodedValue;
        }

        returnValue.__length__++;
    });

    return returnValue;
};

// https://github.com/ChainSafe/web3.js/blob/f2036c0100fb7e74208e9d69914a84eed2cb72b5/packages/web3-eth-abi/src/index.js
async function decodeAndVerify (data) {
	const { messages } = data;
	
	for (let i=0; i<messages.length; ++i) {

		// Decode the data — this works just fine and we get extremely reasonable looking data
		record = Object.values(decodeParameters(['string', 'uint', 'string', 'uint'], messages[i])).slice(0, -1);
        console.log(record);
	}
}

const inputJson = JSON.parse(fs.readFileSync('./sample/sample_output.json', 'utf-8'))
decodeAndVerify(inputJson);