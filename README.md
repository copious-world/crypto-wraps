# crypto-wraps
 
This module exposes convenience methods that wrap around webcrytpo.subtle or window.crypto.subtle, for use in the browser or in node.js. The methods provide a variety of use cases that require several steps with care to how data is passe, e.g. string, buffer, base encoding, encrypted, decrypted, public and private.

## node.js and browser

The browser modules being int the **clients** directory. And, the node.js versions begin in the **lib** directory.

## Methods

All methods except *gen\_nonce* are asynchronous.

* **gen\_nonce**
* **protect\_hash**
* **aes\_encryptor**
* **aes\_decipher\_message**
* **gen\_cipher\_key**
* **protect\_hash**
* **gen\_public\_key**
* **unwrapped\_aes\_key**
* **aes\_to\_str**
* **aes\_from\_str**
* **key\_wrapper**
* **key\_unwrapper**
* **key\_signer**
* **verifier**

## Code Doc - same as comments in code

```
// generate a random vaue -- return it as string

/*
// aes_encryptor
// Parameters:  
//                  encodable -  a string
//                  aes_key - aes_key as buffer
//                  nonce - random (gen_nonce) passed as a buffer
// Returns: The enciphered text
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
// gen_cipher_key
//    -- generates an AES key "AES-CBC",256 for encrypting and decrypting
// Returns: aes_key as a buffer (see crypto.subtle.generateKey)
*/

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

/*
// gen_public_key
// Parameters:
//            -- info - an info object (javascript object) which gain fields info.public_key and info.signer_public_key
//                      optionally provides a field info.biometric, which will be signed and signature will be put into this field
//            -- store_info - a method taking two parameters (info,privates)  privates is the Object created in this method
// 
*/

//>--
// wv_unwrapped_key
// Parameters: 
//            -- wrapped_aes : as a buffer
//            -- unwrapper_key : as a buffer
// --
*/

/*
// aes_to_str 
// Parameters: 
        -- aes_key - the key buffer that will put in the transport type
        -- transport_type :  can be "jwk" or "raw"
  Import an AES secret key from an ArrayBuffer containing the raw bytes.
  Takes an ArrayBuffer string containing the bytes, and returns a Promise
  that will resolve to a CryptoKey representing the secret key.
*/


/*
// aes_from_str
// Parameters:
//        -- aes_key_str 
//        -- transport_type :  can be "jwk" or "raw"
// Returns:  the aes_key buffer
*/

/*
// key_wrapper
// Parameters:
//        -- key_to_wrap  as a huffer
//        -- pub_wrapper_key :  the public key (for instance a receiver key)
// Returns: the wrapped key in a string that can be sent
*/

/*
// key_unwrapper
// Parameters:
//        -- wrapped_key : as a string that can be JSON.parsed into a jwk format object
//        -- piv_wrapper_key :  the private key (for instance a sender key)
// Returns: the unwrapped key in a string that can be sent
*/


/*
// key_signer
// Parameters:
//        -- data_to_sign  as a string 
//        -- priv_signer_key :  the private key (for instance a sender key) for signing 
//                               passed as a string that can be JSON.parserd into a jwk format
// Returns: the a base64url string 
*/

/*
// verifier
// Parameters:
//        -- was_signed_data : as a string that can be JSON parsed
//        -- signer_pub_key :  the public key (for instance a sender key) for verification  
//                               passed as a string that can be JSON.parserd into a jwk format
// Returns: bool
*/


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


```