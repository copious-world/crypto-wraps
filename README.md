# crypto-wraps
 
This module exposes convenience methods that wrap around webcrypto.subtle or window.crypto.subtle, for use in the browser or in node.js. The methods provide a variety of use cases that by themselves require several steps with care to how data is passed in parameters, e.g. string, buffer, base encoding, encrypted, decrypted, public and private. These methods put some of those steps together and take are of many parameter concerns.

## node.js and browser

The browser modules begin in the **clients** directory. And, the node.js versions begin in the **lib** directory.

## Methods

All methods except *gen\_nonce* are asynchronous.

* **gen\_nonce**
* **gen\_cipher\_key**
* **pc\_keypair\_promise** 
* **pc\_wrapper\_keypair_promise**
* **aes\_encryptor**
* **aes\_decipher\_message**
* **galactic\_user\_starter\_keys**
* **protect\_hash**
* **verify\_protect**
* **gen\_public\_key**
* **unwrapped\_aes\_key**
* **key\_wrapper**
* **key\_unwrapper**
* **aes\_to\_str**
* **aes\_from\_str**
* **key\_signer**
* **verifier**
* **decipher\_message**

## Code Doc - same as comments in code

```
// generate a random vaue -- return it as string

/*
// gen_cipher_key
// Parameters: no parameters
//    -- generates an AES key "AES-CBC",256 for encrypting and decrypting
// Returns: aes_key as a buffer (see crypto.subtle.generateKey)
*/

//>--
// pc_keypair_promise
// Parameters: no parameters
// Returns: a Promise that resolves to an elliptic curve key using P-384 with sign and verify privileges
//  -- 

//>--
// pc_wrapper_keypair_promise
// Parameters: no parameters
// Returns: a Promise that resolves to an RSA-OAEP key modulus 4096 hash to SHA-256 with wrapKey and unwrapKey privileges
//  -- 


/*
// aes_encryptor
// Parameters:  
//        encodable -  a string
//   		aes_key - aes_key as CryptoKey
//			nonce - random (gen_nonce) passed as a uint8Array
// Returns: The enciphered text ArrayBuffer
*/


/*
// aes_decipher_message
// Parameters:  
//                  message -  as a uint8Array
//                  aes_key - aes_key as buffer
//                  nonce - random (gen_nonce) passed as a buffer
// Returns: clear text
*/


/*
// galactic_user_starter_keys
// Parameters: no parameters
// 
//    make a priv/pub key pair.
// Return: an object containing all key pairs
//
	let key_info = {
		"pk_str" : pub_key_str,
		"priv_key" : priv_key_str,
		"signer_pk_str"  : sign_pub_key_str,
		"signer_priv_key" : sign_priv_key_str
	}
//
*/

/*
// verify_protected
// Parameters: 
//          -- string_that_was_signed - (just the string as is)
//			-- encrypted_sig - the signature returned by protect_hash
//          -- aes_key - aes key as CryptoKey
//			-- pub_keys - An object containing public keys {pub_keys.signer_pk_str}
//          -- nonce - base64url encoded uint8Array
//          -- string_to_be_signed
// wrap a hash of the biomarker -- done before server create identity operation 
// Returns: As the toString of a Uint8Array  (commad delimited entries, csv)
*/

/*
// protect_hash
// Parameters: 
//          -- priv_keys - structure containing private keys for signing {priv_keys.signer_priv_key}
//          -- aes_key - aes key as CryptoKey
//          -- nonce - base64url encoded uint8Array
//          -- string_to_be_signed
// wrap a hash of the biomarker -- done before server create identity operation 
// Returns: As the toString of a Uint8Array  (commad delimited entries, csv)
*/


/*
// gen_public_key
// Parameters:
//            -- info - an info object (javascript object) which gain fields info.public_key and info.signer_public_key
//                      optionally provides a field info.biometric, which will be signed and signature will be put into this field
//            -- store_info - a method taking two parameters (info,privates)  privates is the Object created in this method
// 
*/

*
//>--
// unwrapped_aes_key
// Parameters: 
//            -- wrapped_aes : as a buffer containing a jwk formatted key
//            -- unwrapper_key : as a buffer the result of importing the key
// Returns: aes_key as a CryptoKey structure (see crypto.subtle.generateKey) with encrypte and decrypt permissions
*/

/*
// key_wrapper
// Parameters:
//        -- key_to_wrap  as Cryptokey
//        -- pub_wrapper_key :  the public wrapper key (for instance a receiver key) as jwk in JSON parseable string
// Returns: the wrapped key in a string that can be sent
*/

/*
// key_unwrapper
// Parameters:
//        -- wrapped_key : as base64url encoded uint8array for passing to unwrapped_aes_key
//        -- piv_wrapper_key :  the private key (for instance a sender key) as a JSON.parseable string representing jwk
// Returns: the unwrapped key in a string that can be sent
*/


/*
// aes_to_str 
// Parameters: 
        -- aes_key - as Cryptokey
        -- transport_type :  can be "jwk" or "raw"
  Export an AES secret key given an ArrayBuffer containing the raw bytes.
// Returns: the export key JSON.stringify if 'jwk' ||  base64url Uint8Array if 'raw'
*/


/*
// aes_from_str
// Parameters:
//        -- aes_key_str  : 	the export key JSON.stringify if 'jwk' 
//        -- transport_type :  can be "jwk" or "raw" ||  base64url Uint8Array if 'raw'
// Returns:  the aes_key Cryptokey the result of import
*/


/*
// key_signer
// Parameters:
//        -- data_to_sign  as a string 
//        -- priv_signer_key :  the private key (for instance a sender key) for signing 
//                              passed as a string that can be JSON.parserd into a jwk format
// Returns: the a base64url string containing the signature
*/


/*
// verifier
// Parameters:
//		-- was_signed_data : as a string that was originially passed to key_signer
//		-- signature : the a base64url string containing the signature
//		-- signer_pub_key :  the public key (for instance a sender key) for verification  
//                           passed as a string that can be JSON.parserd into a jwk format
// Returns: bool
*/


/*
// encipher_message
// Parameters:
//        -- message :  a text string
//        -- aes_key :  as CryptoKey
//        -- nonce : as a string storing a buffer base64url
// Returns: a base64url encoding of the enciphered buffer
*/
async function encipher_message(message,aes_key,nonce) {
	try {
		if ( aes_key ) {
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


/*
// decipher_message
// Parameters:
//        -- message : base64url encoded string return from encipher
//        -- wrapped_key :  aes key in a wrapped state returned from key_wraper
//        -- priv_key : the private key for unwrapping
//        -- nonce : as a string storing a buffer base64url
// Returns: The clear string or false if it cannot be decrypted
*/


```
