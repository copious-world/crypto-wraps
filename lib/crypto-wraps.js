//
const crypto = require('crypto')

const {buffer_from_cvs_array,buffer_from_b64_csv,to_base64,from_base64} = require("./crypto-hash.js")

let g_crypto = crypto.webcrypto.subtle



// generate a random vaue -- return it as string
function gen_nonce() {
	let b = Buffer.from(getRandomValues.getRandomValues(new Uint8Array(16)))
	return b.toString('base64url')
}

/*
// aes_encryptor
// Parameters:  
//                  encodable -  a string
//                  aes_key - aes_key as buffer
//                  nonce - random (gen_nonce) passed as a buffer
// Returns: The enciphered text
*/
async function aes_encryptor(encodable,aes_key,nonce) {

	let enc = new TextEncoder();
  let clear_buf =  enc.encode(encodable);
	let iv = nonce

    let ciphertext = await g_crypto.encrypt({
												name: "AES-CBC",
												iv
											},
											aes_key,
											clear_buf
										);
	return ciphertext
}


/*
// aes_decipher_message
// Parameters:  
//                  message -  as a uint8Array
//                  aes_key - aes_key as buffer
//                  nonce - random (gen_nonce) passed as a buffer
// Returns: clear text
*/
async function aes_decipher_message(message,aes_key,nonce) {
	let iv = nonce
    let decrypted = await g_crypto.decrypt({
												name: "AES-CBC",
												iv
											},
											aes_key,
											message
										);
	//
	let dec = new TextDecoder()
	let clear = dec.decode(decrypted)
	return clear
}
// 

/*
// gen_cipher_key
//    -- generates an AES key "AES-CBC",256 for encrypting and decrypting
// Returns: aes_key as a buffer (see crypto.subtle.generateKey)
*/
async function gen_cipher_key() {
	//
	try {
		let aes_key = g_crypto.generateKey({
												name: "AES-CBC",
												length: 256
											},
											true,
											["encrypt", "decrypt"]
										)	

		return aes_key
	} catch(e){}
	//
	return false
}

/*
// protect_hash
// Parameters: 
//          -- priv_keys
//          -- aes_key
//          -- nonce
//          -- string_to_be_signed
// wrap a hash of the biomarker -- done before server create identity operation 
// Returns: As the toString of a Uint8Array  (commad delimited entries, csv)
*/
async function protect_hash(priv_keys,aes_key,nonce,string_to_be_signed) {
  //
  try {
    const encoder = new TextEncoder();
    const data = encoder.encode(string_to_be_signed);
    const hash = await g_crypto.digest('SHA-256', data);
  
    let priv_signer_key = priv_keys.signer_priv_key
  
    let signer_jwk = JSON.parse(priv_signer_key)
    let signer = await g_crypto.importKey(	"jwk",
                        signer_jwk,
                        {
                          'name': "ECDSA",
                          'namedCurve': "P-384"
                        },
                        true,
                        ["sign"]
                    );
  
    let signature = await g_crypto.sign({
                        name: "ECDSA",
                        hash: {name: "SHA-384"},
                      },
                      signer,
                      hash
                    );
  
    let sig_buff = new Uint8Array(signature)
    let sig_txt = sig_buff.toString()
    let iv_nonce = buffer_from_b64_csv(nonce)
    let cipher_sig = await aes_encryptor(sig_txt,aes_key,iv_nonce)
    //
    let int_rep_enc = new Uint8Array(cipher_sig)
    return int_rep_enc.toString()
  } catch (e) {
    console.log(e)
    return false
  }
}


/*
// gen_public_key
// Parameters:
//            -- info - an info object (javascript object) which gain fields info.public_key and info.signer_public_key
//                      optionally provides a field info.biometric, which will be signed and signature will be put into this field
//            -- store_info - a method taking two parameters (info,privates)  privates is the Object created in this method
// 
*/
async function gen_public_key(info,store_info) {
	let keys = await promail_user_starter_keys()
	//
	info.public_key = keys.pk_str		// user info is the basis for creating a user cid the public key is part of it
	info.signer_public_key = keys.signer_pk_str
	//
	let aes_key = await gen_cipher_key()
	let storable_key = await aes_to_str(aes_key) 
	let nonce = gen_nonce()
	//
	let privates = {		// private keys will be stored locally, and may offloadded from the browser at the user's discretion.
		'priv_key' : keys.priv_key,
		'signer_priv_key' : keys.signer_priv_key,
		'signature_protect' : {
			"key" : storable_key,
			"nonce" : nonce
		}
	}
	info.biometric = await protect_hash(privates,aes_key,nonce,info.biometric)
	if ( store_info ) store_info(info,privates)
}

/*
//>--
// wv_unwrapped_key
// Parameters: 
//            -- wrapped_aes : as a buffer
//            -- unwrapper_key : as a buffer
// --
*/
async function unwrapped_aes_key(wrapped_aes,unwrapper_key) {
  let unwrapped_aes = await g_crypto.unwrapKey(
        "jwk", // same as wrapped
        wrapped_aes, //the key you want to unwrap
        unwrapper_key, //the private key with "unwrapKey" usage flag
        {   //these are the wrapping key's algorithm options
            name: "RSA-OAEP",
            modulusLength: 4096, //can be 1024, 2048, or 4096
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: { name: "SHA-256" }, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
        },
        {   //this what you want the wrapped key to become (same as when wrapping)
            name: "AES-CBC",
            length: 256
        },
        true, //whether the key is extractable (i.e. can be used in exportKey)
        ["encrypt", "decrypt"] //the usages you want the unwrapped key to have
      )
  //
  return unwrapped_aes
}
//--<


/*
// aes_to_str 
// Parameters: 
        -- aes_key - the key buffer that will put in the transport type
        -- transport_type :  can be "jwk" or "raw"
  Import an AES secret key from an ArrayBuffer containing the raw bytes.
  Takes an ArrayBuffer string containing the bytes, and returns a Promise
  that will resolve to a CryptoKey representing the secret key.
*/
async function aes_to_str(aes_key,transport_type) {
	switch ( transport_type ) {
		case "jwk" : {
			const exported = await g_crypto.exportKey("jwk", aes_key);
			let key_str = JSON.stringify(exported)
			return key_str
		}
		case "raw" :
		default: {
			const exported = await g_crypto.exportKey("raw", aes_key);
			const exportedKeyBuffer = new Uint8Array(exported);
			let key_str = exportedKeyBuffer.toString()
			return key_str
		}
	}
}

/*
// importAESKey
// Parameters:
//        -- rawKey 
//        -- transport_type :  can be "jwk" or "raw"
// Returns:  a Promise   (await this function) resolves to a CryptoKey representing the secret key
  Import an AES secret key from an ArrayBuffer containing the raw bytes.
  Takes an ArrayBuffer string containing the bytes.
*/
function importAESKey(rawKey,transport_type) {
  return g_crypto.importKey(
		transport_type,
		rawKey,
		{
			name: "AES-CBC",
			length: 256
		},
		true,
		["encrypt", "decrypt"]
  );
}

/*
// aes_from_str
// Parameters:
//        -- aes_key_str 
//        -- transport_type :  can be "jwk" or "raw"
// Returns:  the aes_key buffer
*/
async function aes_from_str(aes_key_str,transport_type) {
	switch ( transport_type ) {
		case "jwk" : {
			try {
				let key_obj = JSON.parse(aes_key_str)
				let key = await importAESKey(key_obj,"jwk")
				return key
			} catch (e) {}
			break;
		}
		case "raw" :
		default: {
			let els = aes_key_str.split(',').map(el => parseInt(el))
			let buf = new Uint8Array(els)
			let key = await importAESKey(buf,"raw")
			return key
		}
	}
}


/*
// key_wrapper
// Parameters:
//        -- key_to_wrap  as a huffer
//        -- pub_wrapper_key :  the public key (for instance a receiver key)
// Returns: the wrapped key in a string that can be sent
*/
async function key_wrapper(key_to_wrap,pub_wrapper_key) {
	try {
		let wrapper_jwk = JSON.parse(pub_wrapper_key)
		let wrapper = await g_crypto.importKey(
				"jwk",
				wrapper_jwk,
				{   //these are the wrapping key's algorithm options
					name: "RSA-OAEP",
					modulusLength: 4096, //can be 1024, 2048, or 4096
					publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
					hash: { name: "SHA-256" }, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
				},
				true,
				["wrapKey"]
		);

		let wrapped_key = await g_crypto.wrapKey(
											"jwk",
											key_to_wrap,
											wrapper,
											{   //these are the wrapping key's algorithm options
												name: "RSA-OAEP"
											}
										);
		let type8 = new Uint8Array(wrapped_key)
		let tranportable = to_base64(type8)
		return tranportable
	} catch(e) {
		console.log(e)
	}
	return false
}


/*
// key_unwrapper
// Parameters:
//        -- wrapped_key : as a string that can be JSON.parsed into a jwk format object
//        -- piv_wrapper_key :  the private key (for instance a sender key)
// Returns: the unwrapped key in a string that can be sent
*/
async function key_unwrapper(wrapped_key,piv_wrapper_key) {
	let wrapper_jwk = JSON.parse(piv_wrapper_key)
	let unwrapper = await g_crypto.importKey(
			"jwk",
			wrapper_jwk,
			{   //these are the wrapping key's algorithm options
				name: "RSA-OAEP",
				modulusLength: 4096, //can be 1024, 2048, or 4096
				publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
				hash: { name: "SHA-256" }, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
			},
			true,
			["unwrapKey"]
	);
	
	// wrapped_key
	let wrapped_aes =  from_base64(wrapped_key)
	let aes_key = await unwrapped_aes_key(wrapped_aes,unwrapper)
	return aes_key
}


/*
// key_signer
// Parameters:
//        -- data_to_sign  as a string 
//        -- priv_signer_key :  the private key (for instance a sender key) for signing 
//                               passed as a string that can be JSON.parserd into a jwk format
// Returns: the a base64url string 
*/
async function key_signer(data_to_sign,priv_signer_key) {
	try {
		let signer_jwk = JSON.parse(priv_signer_key)
		let signer = await g_crypto.importKey(
				"jwk",
				signer_jwk,
				{
					'name': "ECDSA",
					'namedCurve': "P-384"
				},
				true,
				["sign"]
		);

		let enc = new TextEncoder();
		let signable = enc.encode(data_to_sign);
		let signature = await g_crypto.sign({
												name: "ECDSA",
												hash: {name: "SHA-384"},
											},
											signer,
											signable
										);

		let type8 = new Uint8Array(signature)
		let tranportable = to_base64(type8)
		return tranportable
	} catch(e) {
		console.log(e)
	}
	return false
}


/*
// verifier
// Parameters:
//        -- was_signed_data : as a string that can be JSON parsed
//        -- signer_pub_key :  the public key (for instance a sender key) for verification  
//                               passed as a string that can be JSON.parserd into a jwk format
// Returns: bool
*/
async function verifier(was_signed_data,signature,signer_pub_key) {
	try {
		let signer_jwk = JSON.parse(signer_pub_key)
		let verifier = await g_crypto.importKey(
				"jwk",
				signer_jwk,
				{
					'name': "ECDSA",
					'namedCurve': "P-384"
				},
				true,
				["verify"]
		);
		//
		let enc = new TextEncoder();
		let verifiable = enc.encode(was_signed_data);

		let sig_bytes = from_base64(signature)

		let result = await g_crypto.verify({
											name: "ECDSA",
											hash: {name: "SHA-384"},
										},
										verifier,
										sig_bytes,
										verifiable
									);
		return result
	}  catch(e) {
		console.log(e)
	}
}


/*
// decipher_message
// Parameters:
//        -- message :  as a string storing a buffer formatted as csv of the entries
//        -- wrapped_key :  the public key (for instance a sender key) for verification  
//                           passed as a string that can be JSON.parsed into a jwk format object
//        -- priv_key : the private key for unwrapping
//        -- nonce : as a string storing a buffer as csv of the entries
// Returns: bool
*/
async function decipher_message(message,wrapped_key,priv_key,nonce) {
	try {
		let aes_key = await key_unwrapper(wrapped_key,priv_key)
		if ( aes_key ) {
			let iv_nonce = buffer_from_b64_csv(nonce)
			let buffer = buffer_from_cvs_array(message)
			let clear = await aes_decipher_message(buffer,aes_key,iv_nonce)
			return clear
		}
	} catch(e) {
		console.log(e)
	}
	return false
}
// 




module.exports.gen_nonce = gen_nonce
module.exports.protect_hash = protect_hash
module.exports.aes_encryptor = aes_encryptor
module.exports.aes_decipher_message = aes_decipher_message
//
module.exports.gen_cipher_key = gen_cipher_key
module.exports.protect_hash = protect_hash
module.exports.gen_public_key = gen_public_key
module.exports.unwrapped_aes_key = unwrapped_aes_key
module.exports.aes_to_str = aes_to_str
module.exports.importAESKey = importAESKey
module.exports.aes_from_str = aes_from_str
module.exports.key_wrapper = key_wrapper
module.exports.key_unwrapper = key_unwrapper
module.exports.key_signer = key_signer
module.exports.verifier = verifier
