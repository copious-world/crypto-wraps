// MODULE: CRYPTO WRAPS (node)

// sometimes code doesn't want to be a module. But, there is a module version of this in npm crypto-wraps
//
//
const crypto = require('crypto')

const {to_base64_from_uint8array,from_base64_to_uint8array} = require("./crypto-hash.js")
// ---- ---- ---- ---- ---- ---- ---- ----
// ---- ---- ---- ---- ---- ---- ---- ----

let g_crypto = crypto.webcrypto.subtle

//$>>	gen_nonce
/*
// gen_nonce
// Parameters: optional parameter
// 	--	no parameter case
// 	--	generate a random vaue -- return it as string
// 	--	parameter (optional) : A base64url string that is at least 16 bytes
//		-- returns the the first bytes as a base64url string (for deriving an IV from data) Not random
// 
// Returns a nonce as a base64url string representing 16 bytes = 128 bits
*/
function gen_nonce(input_bits) {
	if ( input_bits === undefined ) {
		let random = crypto.webcrypto.getRandomValues(new Uint8Array(16))
		return to_base64_from_uint8array(random)
	} else {
		let bytes = from_base64_to_uint8array(input_bits)
		bytes = bytes.subarray(0, 16)
		return to_base64_from_uint8array(bytes)
	}
}

//$>>	gen_cipher_key
/*
// gen_cipher_key
//    -- generates an AES key "AES-CBC",256 for encrypting and decrypting
// Returns: aes_key as a CryptoKey structure (see crypto.subtle.generateKey)
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


//$>>	keypair_promise
//>--
// keypair_promise
// Parameters: no parameters
// Returns: a Promise that resolves to an elliptic curve key using P-384 with sign and verify privileges
//  -- 
function keypair_promise() {  // return 
    // Generate a local public/private key pair
    let p =  g_crypto.generateKey({
            'name': "ECDSA",
            'namedCurve': "P-384"
        },
        true,
        ["sign", "verify"]
    )
    return p  // promise
}
//-


//$>>	axiom_keypair_promise
//>--
// axiom_keypair_promise
// Parameters: no parameters
// Returns: a Promise that resolve to an elliptic curve key using P-384 with cipher key derivation privileges. Allows for deriving AES 256 cipher key
//  -- 
function axiom_keypair_promise() {
    // Generate a local public/private key pair
    let p =  g_crypto.generateKey({
            'name': "ECDH",
            'namedCurve': "P-384"
        },
        true,
        ["deriveKey"]
    )
    return p  // promise
}


//$>>	wrapper_keypair_promise
//>--
// wrapper_keypair_promise
// Parameters: no parameters
// Returns: a Promise that resolves to an RSA-OAEP key modulus 4096 hash to SHA-256 with wrapKey and unwrapKey privileges
//  -- 
function wrapper_keypair_promise() {  // return 
    // Generate a local public/private key pair
    let p =  g_crypto.generateKey({
            name: "RSA-OAEP",
            modulusLength: 4096, //can be 1024, 2048, or 4096
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: { name: "SHA-256" }, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
        },
        true,
        ["wrapKey","unwrapKey"]
    )
    return p  // promise
}
//--<


//$>>	aes_encryptor
/*
// aes_encryptor
// Parameters:  
//        		encodable -  a string or a uint8array
//   			aes_key - aes_key as CryptoKey
//				nonce - random (gen_nonce) passed as a uint8Array
// Returns: The enciphered text ArrayBuffer
*/
async function aes_encryptor(encodable,aes_key,nonce) {

	let clear_buf = false
	if ( typeof encodable === 'string' ) {
		let enc = new TextEncoder();
		clear_buf =  enc.encode(encodable);
	} else if ( (encodable.constructor.name === 'Uint8Array') ||  (encodable.constructor.name === 'Buffer') ) {
		clear_buf = encodable
	}

	if ( clear_buf ) {
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

	return false
}


//$>>	aes_decipher_message
/*
// aes_decipher_message
// Parameters:  
//  			message -  as a uint8Array
//				aes_key - aes key as CryptoKey
//				nonce - random (gen_nonce) passed as a uint8Array
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

// 


//$>>	galactic_user_starter_keys
/*
// galactic_user_starter_keys
// Parameters: no parameters or (optional) a selector parameter
// 
// Optional parameters values:  "wrapper", "signer"  
//								Purpose:  produce only the selected key pair
//    make a priv/pub key pair.
// Return: an object containing all key pairs
//
	let key_info = {
		"pk_str" : pub_key_str,
		"priv_key" : priv_key_str,
		"signer_pk_str"  : sign_pub_key_str,
		"signer_priv_key" : sign_priv_key_str
		"axiom_pk_str" : axiom_pub_key_str,
		"axiom_priv_key" : axiom_priv_key_str		
	}
//
*/
async function galactic_user_starter_keys(selector) {
	//
	let pub_key_str = false
	let priv_key_str = false
	if ( (selector === undefined) || (selector === "wrapper") ) {
		// Generate a local public/private key pair WRAPPER
		let keypair = await wrapper_keypair_promise()
		// ---- ---- ---- ----
		let pub_key = keypair.publicKey
		let priv_key = keypair.privateKey
		// ---- ---- ---- ----                                      // g_nonce_buffer - space to use
		let exported = await g_crypto.exportKey("jwk",pub_key);
		pub_key_str = JSON.stringify(exported)

		let priv_exported = await g_crypto.exportKey("jwk",priv_key);
		priv_key_str =  JSON.stringify(priv_exported);
	}

	let sign_pub_key_str = false
	let sign_priv_key_str = false
	if ( (selector === undefined) || (selector === "signer") ) {
		// Generate a local public/private key pair SIGNER
		let signer_pair = await keypair_promise()

		let signer_pub_key = signer_pair.publicKey
		let signer_priv_key = signer_pair.privateKey

		let sign_exported = await g_crypto.exportKey("jwk",signer_pub_key);
		sign_pub_key_str = JSON.stringify(sign_exported)

		let sign_priv_exported = await g_crypto.exportKey("jwk",signer_priv_key);
		sign_priv_key_str =  JSON.stringify(sign_priv_exported);
	}


	let axiom_pub_key_str = false
	let axiom_priv_key_str = false
	if ( (selector === undefined) || (selector === "derive") ) {
		// Generate a local public/private key pair SIGNER
		let axiom_pair = await axiom_keypair_promise()

		let axiom_pub_key = axiom_pair.publicKey
		let axiom_priv_key = axiom_pair.privateKey

		let axiom_exported = await g_crypto.exportKey("jwk",axiom_pub_key);
		axiom_pub_key_str = JSON.stringify(axiom_exported)

		let axiom_priv_exported = await g_crypto.exportKey("jwk",axiom_priv_key);
		axiom_priv_key_str =  JSON.stringify(axiom_priv_exported);
	}

	//
	let key_info = {
		"pk_str" : pub_key_str,
		"priv_key" : priv_key_str,
		"signer_pk_str"  : sign_pub_key_str,
		"signer_priv_key" : sign_priv_key_str,
		"axiom_pk_str" : axiom_pub_key_str,
		"axiom_priv_key" : axiom_priv_key_str
	}

	if ( key_info.pk_str === false ) {
		delete key_info.pk_str
		delete key_info.priv_key
	}
	if ( key_info.signer_pk_str === false ) {
		delete key_info.signer_pk_str
		delete key_info.signer_priv_key
	}
	if ( key_info.axiom_pk_str === false ) {
		delete key_info.axiom_pk_str
		delete key_info.axiom_priv_key
	}

	return(key_info)
}




//$>>	protect_hash
/*
// protect_hash
// Parameters: 
//          -- priv_keys - structure containing private keys for signing {priv_keys.signer_priv_key}
//          -- aes_key - aes key as CryptoKey
//          -- nonce - base64url encoded uint8Array
//          -- string_to_be_signed
// use to wrap a hash of the biomarker -- done before server create identity operation 
// Returns: As the toString of a Uint8Array  (commad delimited entries, csv)
*/

async function protect_hash(priv_keys,aes_key,nonce,string_to_be_signed) {
	//
	try {
		let priv_signer_key = priv_keys.signer_priv_key
		let sig_txt = await key_signer(string_to_be_signed,priv_signer_key)
		let iv_nonce = from_base64_to_uint8array(nonce)
		let cipher_sig = await aes_encryptor(sig_txt,aes_key,iv_nonce)
		//
		let cipher_sig_buf = new Uint8Array(cipher_sig)
		return to_base64_from_uint8array(cipher_sig_buf)
	} catch (e) {
	  console.log(e)
	  return false
	}
	//
}


//$>>	verify_protected
/*
// verify_protected
// Parameters: 
//          -- string_that_was_signed - (just the string as is)
//			-- encrypted_sig - the signature returned by protect_hash
//			-- pub_keys - An object containing public keys {pub_keys.signer_pk_str}
//          -- aes_key - aes key as CryptoKey
//          -- nonce - base64url encoded uint8Array
// wrap a hash of the biomarker -- done before server create identity operation 
// Returns: As the toString of a Uint8Array  (commad delimited entries, csv)
*/

async function verify_protected(string_that_was_signed,encrypted_sig,pub_keys,aes_key,nonce) {
	try {
		let signer_pk_str = pub_keys.signer_pk_str
		let iv_nonce = from_base64_to_uint8array(nonce)
		let cipher_sig = await from_base64_to_uint8array(encrypted_sig)
		let clear_sig =  await g_crypto.decrypt({
													name: "AES-CBC",
													iv  : iv_nonce
												},
												aes_key,
												cipher_sig
											);
		const decoder = new TextDecoder();
		let sig_txt = decoder.decode(clear_sig);
		//
		let verified = await verifier(string_that_was_signed,sig_txt,signer_pk_str)
		return verified
	} catch (e) {
		console.log(e)
	}
	return false
}


//$>>	unwrapped_aes_key
/*
//>--
// unwrapped_aes_key
// Parameters: 
//            -- wrapped_aes : as a buffer containing a jwk formatted key
//            -- unwrapper_key : as a buffer the result of importing the key
// Returns: aes_key as a CryptoKey structure (see crypto.subtle.generateKey) with encrypte and decrypt permissions
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


//$>>	derive_aes_key
/*
//>--
// derive_aes_key
// Parameters: 
//            -- remote_pub_key_buffer : as a buffer containing a jwk formatted key
//            -- local_private : as a buffer the result of importing the key
// Returns: aes_key as a CryptoKey structure (see crypto.subtle.generateKey) with encrypte and decrypt permissions
*/
async function derive_aes_key(remote_pub_key_buffer,local_private) {
	let derived_aes = await g_crypto.deriveKey(
	  {
		name: "ECDH",
		public: remote_pub_key_buffer
	  },
	  local_private,
	  {
		name: "AES-CBC",
		length: 256
	  },
	  false,
	  ["encrypt", "decrypt"]
	);

	return derived_aes
}


//$>>	key_wrapper
/*
// key_wrapper
// Parameters:
//        -- key_to_wrap  as Cryptokey
//        -- pub_wrapper_key :  the public wrapper key (for instance a receiver key) as jwk in JSON parseable string
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
		let tranportable = to_base64_from_uint8array(type8)
		return tranportable
	} catch(e) {
		console.log(e)
	}
	return false
}


//$>>	key_unwrapper
/*
// key_unwrapper
// Parameters:
//        -- wrapped_key : as base64url encoded uint8array for passing to unwrapped_aes_key
//        -- piv_wrapper_key :  the private key (for instance a sender key) as a JSON.parseable string representing jwk
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
	let wrapped_aes = from_base64_to_uint8array(wrapped_key)
	let aes_key = await unwrapped_aes_key(wrapped_aes,unwrapper)
	return aes_key
}



//$>>	derive_key
/*
// derive_key
// Parameters:
//        -- sender_public_key : base64 buffer of a ECDH public key with derivation privileges.
//        -- piv_axiom_key :  the private key (for instance a sender key) as a JSON.parseable string representing jwk derivation privileges.
// Returns: the derived key in a string that can be sent
*/
async function derive_key(sender_public_key,piv_axiom_key) {
	let axiom_jwk = JSON.parse(piv_axiom_key)
	let local_private = await g_crypto.importKey(
			"jwk",
			axiom_jwk,
			{
				'name': "ECDH",
				'namedCurve': "P-384"
			},
			true,
			["deriveKey"]
	);
	// wrapped_key
	let sender_pub_key_buffer = from_base64_to_uint8array(sender_public_key)
	let aes_key = await derive_aes_key(sender_pub_key_buffer,local_private)
	return aes_key
}



//$>>	aes_to_str
/*
// aes_to_str 
// Parameters: 
        -- aes_key - as Cryptokey
        -- transport_type :  can be "jwk" or "raw"
  Export an AES secret key given an ArrayBuffer containing the raw bytes.
// Returns: the export key JSON.stringify if 'jwk' ||  base64url Uint8Array if 'raw'
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
			let key_str = to_base64_from_uint8array(exportedKeyBuffer)
			return key_str
		}
	}
}



//$>>	ecdh_to_str
/*
// ecdh_to_str 
// Parameters: 
        -- ecdh_key - as Cryptokey
        -- transport_type :  can be "jwk" or "raw"
  Export an AES secret key given an ArrayBuffer containing the raw bytes.
// Returns: the export key JSON.stringify if 'jwk' ||  base64url Uint8Array if 'raw'
*/

async function ecdh_to_str(ecdh_key,transport_type) {
	switch ( transport_type ) {
		case "jwk" : {
			const exported = await g_crypto.exportKey("jwk", ecdh_key);
			exported.key_ops = [ 'deriveKey' ]   // this had to be added ?? is it a bug with key generation?
			let key_str = JSON.stringify(exported)
			return key_str
		}
		case "raw" :
		default: {
			const exported = await g_crypto.exportKey("raw", ecdh_key);
			const exportedKeyBuffer = new Uint8Array(exported);
			let key_str = to_base64_from_uint8array(exportedKeyBuffer)
			return key_str
		}
	}
}

//$>>	importAESKey
/*
// importAESKey
// Parameters:
//        -- rawKey or JWK object
//        -- transport_type :  can be "jwk" or "raw"
// Returns:  a Promise   (await this function) resolves to a CryptoKey representing the secret key
  Import an AES secret key from an ArrayBuffer containing the raw bytes.
  Takes an ArrayBuffer containing the bytes or a JWK object.
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



//$>>	importECDHKey
/*
// importECDHKey
// Parameters:
//        -- rawKey or JWK object
//        -- transport_type :  can be "jwk" or "raw"
// Returns:  a Promise   (await this function) resolves to a CryptoKey representing the secret key
  Import an ECDH secret key from an ArrayBuffer containing the raw bytes or from JWK.
  Takes an ArrayBuffer string containing the bytes.
*/
function importECDHKey(axiomKey,transport_type) {
	if ( typeof axiomKey === "string" ) {
		axiomKey = JSON.parse(axiomKey)
	}
	if ( transport_type === 'jwk' ) {
		if ( (axiomKey.key_ops === undefined) || ( Array.isArray(axiomKey.key_ops) && axiomKey.key_ops.length === 0 ) ) {
			axiomKey.key_ops = ["deriveKey"]
		}
	}
	return g_crypto.importKey(
		transport_type,
		axiomKey,
		{
			'name': "ECDH",
			'namedCurve': "P-384"
		},
		true,
		["deriveKey"]
	);
}

  

//$>>	aes_from_str
/*
// aes_from_str
// Parameters:
//        -- aes_key_str  : 	the export key JSON.stringify if 'jwk' 
//        -- transport_type :  can be "jwk" or "raw" ||  base64url Uint8Array if 'raw'
// Returns:  the aes_key Cryptokey the result of import
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
			let buf = from_base64_to_uint8array(aes_key_str)
			let key = await importAESKey(buf,"raw")
			return key
		}
	}
}


//$>>	key_signer
/*
// key_signer
// Parameters:
//        -- data_to_sign  as a string 
//        -- priv_signer_key :  the private key (for instance a sender key) for signing 
//                              passed as a string that can be JSON.parsed into a jwk format
// Returns: the a base64url string containing the signature
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
		let tranportable = to_base64_from_uint8array(type8)
		return tranportable
	} catch(e) {
		console.log(e)
	}
	return false
}


//$>>	verifier
/*
// verifier
// Parameters:
//		-- was_signed_data : as a string that was originially passed to key_signer
//		-- signature : the a base64url string containing the signature
//		-- signer_pub_key :  the public key (for instance a sender key) for verification  
//                           passed as a string that can be JSON.parserd into a jwk format
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

		let sig_bytes = from_base64_to_uint8array(signature)

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
	return false
}

//$>>	encipher_message
/*
// encipher_message
// Parameters:
//        -- message :  a text string
//        -- aes_key :  as CryptoKey
//        -- nonce : as a string storing a buffer base64url
// Returns: a base64url encoding of the enciphered buffer
*/
async function encipher_message(message,aes_key,nonce,no_string) {
	try {
		if ( aes_key ) {
			let iv_nonce = from_base64_to_uint8array(nonce)
			let enciphered = await aes_encryptor(message,aes_key,iv_nonce)
			let b8a = new Uint8Array(enciphered)
			if ( no_string ) {
				return b8a
			} else {
				return to_base64_from_uint8array(b8a)
			}
		}
	} catch(e) {
		console.log(e)
	}
	return false
}
// 


//$>>	derived_encipher_message
/*
// derived_encipher_message
// Parameters:
//        -- message :  a text string
//        -- remote_public_ky :  as CryptoKey
//		  -- local_private_ky :  as CryptoKey
//        -- nonce : as a string storing a buffer base64url
// Returns: a base64url encoding of the enciphered buffer
*/
async function derived_encipher_message(message,remote_public_ky,local_private_ky,nonce) {
	try {
		if ( remote_public_ky && local_private_ky ) {
			let aes_key = await derive_aes_key(remote_public_ky,local_private_ky)
			let iv_nonce = from_base64_to_uint8array(nonce)
			let enciphered = await aes_encryptor(message,aes_key,iv_nonce)
			let b8a = new Uint8Array(enciphered)
			return to_base64_from_uint8array(b8a)
		}
	} catch(e) {
		console.log(e)
	}
	return false
}
// 

//$>>	decipher_message
/*
// decipher_message
// Parameters:
//        -- message :  base64url encoded string returned from encipher
//        -- wrapped_key :  wrapped aes key 
//                          passed as a string that can be JSON.parsed into a jwk format object
//        -- priv_key : the private key for unwrapping
//        -- nonce : as a string storing a buffer base64url
// Returns: The clear string or false if it cannot be decrypted
*/
async function decipher_message(message,wrapped_key,priv_key,nonce) {
	try {
		let aes_key = await key_unwrapper(wrapped_key,priv_key)
		if ( aes_key ) {
			let iv_nonce = from_base64_to_uint8array(nonce)
			let buffer = from_base64_to_uint8array(message)
			let clear = await aes_decipher_message(buffer,aes_key,iv_nonce)
			return clear
		}
	} catch(e) {
		console.log(e)
	}
	return false
}
// 


//$>>	derived_decipher_message
/*
// derived_decipher_message
// Parameters:
//        -- message :  base64url encoded string returned from encipher
//        -- remote_public : a pubic key for ECDH P-384 key encryption 
//                          passed as a string that can be JSON.parsed into a jwk format object
//        -- priv_key : the private key forming the local counterpart to the sender_public key.
//        -- nonce : as a string storing a buffer base64url
// Returns: The clear string or false if it cannot be decrypted
*/
async function derived_decipher_message(message,remote_public,priv_key,nonce) {
	try {
		let aes_key = await derive_key(remote_public,priv_key)
		if ( aes_key ) {
			let iv_nonce = from_base64_to_uint8array(nonce)
			let buffer = from_base64_to_uint8array(message)
			let clear = await aes_decipher_message(buffer,aes_key,iv_nonce)
			return clear
		}
	} catch(e) {
		console.log(e)
	}
	return false
}
// 



async function derived_decipher_message_jwk(message,remote_public,priv_key,nonce) {
	try {
		let aes_key = await derive_key_jwk(remote_public,priv_key)
		if ( aes_key ) {
			let iv_nonce = from_base64_to_uint8array(nonce)
			let buffer = from_base64_to_uint8array(message)
			let clear = await aes_decipher_message(buffer,aes_key,iv_nonce)
			return clear
		}
	} catch(e) {
		console.log(e)
	}
	return false
}


//$>>	gen_public_key
/*
// gen_public_key
// Parameters:
//     		-- info - an info object (javascript object) which has fields info.public_key and info.signer_public_key
//                      optionally provides a field info.biometric, which will be signed and signature will be put into this field
//       	-- store_info - a method taking two parameters (info,privates)  privates is the Object created in this method
*/
async function gen_public_key(info,store_info) {
	let keys = await galactic_user_starter_keys()
	//
	info.public_key = keys.pk_str		// user info is the basis for creating a user cid the public key is part of it
	info.signer_public_key = keys.signer_pk_str
	info.axiom_public_key = keys.axiom_pk_str
	//
	let aes_key = await gen_cipher_key()
	let storable_key = await aes_to_str(aes_key) 
	let nonce = gen_nonce()
	//
	let privates = {		// private keys will be stored locally, and may offloadded from the browser at the user's discretion.
		'priv_key' : keys.priv_key,
		'signer_priv_key' : keys.signer_priv_key,
		'axiom_priv_key' : keys.axiom_priv_key,
		'signature_protect' : {
			"key" : storable_key,
			"nonce" : nonce
		}
	}
	info.biometric = await protect_hash(privates,aes_key,nonce,info.biometric)
	if ( store_info ) store_info(info,privates)
}

// 

//$$EXPORTABLE::
module.exports.gen_nonce = gen_nonce
module.exports.gen_cipher_key = gen_cipher_key
module.exports.keypair_promise = keypair_promise
module.exports.axiom_keypair_promise = axiom_keypair_promise
module.exports.wrapper_keypair_promise = wrapper_keypair_promise
module.exports.aes_encryptor = aes_encryptor
module.exports.aes_decipher_message = aes_decipher_message
module.exports.galactic_user_starter_keys = galactic_user_starter_keys
module.exports.protect_hash = protect_hash
module.exports.verify_protected = verify_protected
module.exports.unwrapped_aes_key = unwrapped_aes_key
module.exports.derive_aes_key = derive_aes_key
module.exports.key_wrapper = key_wrapper
module.exports.key_unwrapper = key_unwrapper
module.exports.derive_key = derive_key
module.exports.aes_to_str = aes_to_str
module.exports.ecdh_to_str = ecdh_to_str
module.exports.importAESKey = importAESKey
module.exports.importECDHKey = importECDHKey
module.exports.aes_from_str = aes_from_str
module.exports.key_signer = key_signer
module.exports.verifier = verifier
module.exports.encipher_message = encipher_message
module.exports.derived_encipher_message = derived_encipher_message
module.exports.decipher_message = decipher_message
module.exports.derived_decipher_message = derived_decipher_message
//
module.exports.gen_public_key = gen_public_key
module.exports.derived_decipher_message_jwk = derived_decipher_message_jwk


