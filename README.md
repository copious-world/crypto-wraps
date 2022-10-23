# crypto-wraps
 
This module exposes convenience methods that wrap around webcrypto.subtle or window.crypto.subtle, for use in the browser or in node.js.

The methods provide a variety of use cases that by themselves require several steps with care to how data is passed in parameters, e.g. string, buffer, base encoding, encrypted, decrypted, public and private. These methods put some of those steps together and take care of many parameter concerns.

## install

**node.js**

```
npm -i --save crypto-wraps
```


**browser**

```
npm -i --save-dev crypto-wraps
```


<a name="method-list" ></a>

## Methods


All methods except *gen\_nonce* are asynchronous.

* [**gen\_nonce**](#gen-nonce)
* [**gen\_cipher\_key**](#gen_cipher_key)
* [**keypair\_promise**](#keypair_promise)
* [**axiom\_keypair\_promise**](#axiom_keypair_promise)
* [**wrapper\_keypair\_promise**](#wrapper_keypair_promise)
* [**aes\_encryptor**](#aes_encryptor)
* [**aes\_decipher\_message**](#aes_decipher_message)
* [**asymmetric\_starter\_keys**](#asymmetric_starter_keys)
* [**galactic\_user\_starter\_keys**](#galactic_user_starter_keys) (synonym for asymmetric\_starter\_key)
* [**protect\_hash**](#protect_hash)
* [**verify\_protected**](#verify_protected)
* [**unwrapped\_aes\_key**](#unwrapped_aes_key)
* [**derive\_aes\_key**](#derive_aes_key)
* [**key\_wrapper**](#key_wrapper)
* [**key\_unwrapper**](#key_unwrapper)
* [**derive\_key**](#derive_key)
* [**aes\_to\_str**](#aes_to_str)
* [**ecdh\_to\_str**](#ecdh_to_str)
* [**importAESKey**](#importAESKey)
* [**importECDHKey**](#importECDHKey)
* [**aes\_from\_str**](#aes_from_str)
* [**key\_signer**](#key_signer)
* [**verifier**](#verifier)
* [**encipher\_message**](#encipher_message)
* [**decipher\_message**](#decipher_message)
* [**derived\_decipher\_message**](#derived_decipher_message)
* [**gen\_public\_key**](#gen_public_key)





## Code Doc - same as comments in code

<a name="gen-nonce" > </a>

* **gen\_nonce**

>  generate a random vaue -- return it as string
> 
> **Parameters** {two cases}
> 
> ***no parameter case***
>> **Returns:** a random integer (nonce) as a base64url string representing 16 bytes = 128 bits
>
> ***one parameter case***
> > **Returns:** the first 16 bytes as a base64url string (for deriving an IV from data).  
> > The result is NOT random

[**contents**](#method-list)

------------------------------------------------------------------------

<a name="gen_cipher_key" > </a>

* **gen\_cipher\_key**

>  **Parameters** {no parameters}
> 
> Generates an **AES** key **AES-CBC**, 256 with ***encrypting*** and ***decrypting*** privileges
> 
> **Returns**: aes_key as a buffer (see crypto.subtle.generateKey)

[**contents**](#method-list)

------------------------------------------------------------------------

<a name="keypair_promise" > </a>

* **keypair\_promise**

>  **Parameters** {no parameters}
> 
> Prepares an **ECDSA** **P-384** key pair with ***sign*** and ***verify*** privileges
> 
> **Returns**: A promise that resolve to an ECDSA P-384 key pair

**Use case:**

```
async function afoo() {
	let keypair = await keypair_promise()
	let pub_key = keypair.publicKey
	let priv_key = keypair.privateKey
	...
}
```

[**contents**](#method-list)

------------------------------------------------------------------------


<a name="axiom_keypair_promise" > </a>

* **axiom\_keypair\_promise**

>  **Parameters** {no parameters}
> 
> Generates an **ECDH** on curve **P-384**, with ***derivation*** privileges
> 
> **Returns**: A promise resolving to ECDH P-384  as a buffer (see crypto.subtle.generateKey)

**Use case:**

```
async function afoo() {
	let axiom_pair = await axiom_keypair_promise()
	let axiom_pub_key = axiom_pair.publicKey
	let axiom_priv_key = axiom_pair.privateKey
	...
}
```

[**contents**](#method-list)

------------------------------------------------------------------------

<a name="wrapper_keypair_promise" > </a>

* **wrapper\_keypair\_promise**

>  **Parameters** {no parameters}
> 
> Generates an **RSA-OAEP** key modulus 4096 hash to **SHA-256** with ***wrapKey*** and ***unwrapKey*** privileges
> 
> **Returns**: A promise resolving to RSA-OAEP as a buffer (see crypto.subtle.generateKey)
>

**Use case:**

```
async function afoo() {
	let wrapper_pair = await wrapper_keypair_promise()
	let wrapper_pub_key = wrapper_pair.publicKey
	let wrapper_priv_key = wrapper_pair.privateKey
	...
}
```


[**contents**](#method-list)

------------------------------------------------------------------------


<a name="aes_encryptor" > </a>

* **aes\_encryptor**

>  **Parameters** {
> 
```
encodable -  a string
aes_key - aes_key as CryptoKey
nonce - random (gen_nonce) passed as a uint8Array
```
> }
> 
> Encrypts the encodable (text for TextEncoder or an Uint8Array buffer). Use the AES key allowing for "AES-CBC" encryption. The nonce is used as the initialization vector.
> 
> **Returns**: The enciphered text ArrayBuffer
>

**Use case:**

```
async function afoo() {
	let some_txt = "the quick brown fox has a thing with fences."
	let nonce = gen_nonce()
	let iv_nonce = from_base64_to_uint8array(nonce)
	let cipher_buffer = await aes_encryptor(some_txt,aes_key,iv_nonce)
	...
}
```


[**contents**](#method-list)

------------------------------------------------------------------------


<a name="aes_decipher_message" > </a>

* **aes\_decipher\_message**

>  **Parameters** {
> 
```
encrypted -  a string
aes_key - aes_key as CryptoKey
nonce - random (gen_nonce) passed as a uint8Array
```

> }
> 
> Decrypts the encoded (text from a TextEncoder or an Uint8Array buffer). Use the AES key allowing for "AES-CBC" decryption. The nonce is the initialization vector used for encrypting.
> 
> **Returns**:  Clear text (decoded)
>

**Use case:**

```
async function afoo(cipher_buffer, aes_key, nonce) {
	let iv_nonce = from_base64_to_uint8array(nonce)
	let clear_text = await aes_decipher_message(cipher_buffer,aes_key,iv_nonce)
	console.log(clear_text)
	...
}
```


[**contents**](#method-list)

------------------------------------------------------------------------

<a name="galactic_user_starter_keys" > </a>
<a name="asymmetric_starter_keys" > </a>

* **asymetric\_user\_starter\_keys**
* **galactic\_user\_starter\_keys (synonym)**

>  **Parameters** { selector : string } 
> 
> Generates three public/private key pairs for an application, where the applicaton is often assigning the pairs to a single user. (Call this once for each user). The three pairs are generated unless a selector is passed. If the selector is passed, just one key pair will be generated. Here is a list of the selectors:

* "wrapper"
* "signer"
* "derive"

> **Returns**:  an objects with either one selected pair or all pairs. With all the pairs, the returned object looks like the following:

```
	{
		"pk_str" : pub_key_str,			       // wrapper pair
		"priv_key" : priv_key_str,
		"signer_pk_str"  : sign_pub_key_str,   // signer pair
		"signer_priv_key" : sign_priv_key_str,
		"axiom_pk_str" : axiom_pub_key_str,    // derivation pair
		"axiom_priv_key" : axiom_priv_key_str
	}
```

> Note that the keys are generated by previously defined methods: `wrapper_keypair_promise`, `keypair_promise`, and `axiom_keypair_promise`.
> 


**Use case:**

```
async function afoo() {
	let key_pairs = await asymmetric_starter_keys()
	...
	let derivation_keys = await galactic_user_starter_keys("derive")
}
```

**NOTE**: `galactic_user_starter_keys` is named for use in making intergalactic identities.

[**contents**](#method-list)

------------------------------------------------------------------------


<a name="protect_hash" > </a>

* **protect\_hash**

>  **Parameters** {
> 
```
priv_keys - a structure containing private keys for signing {priv_keys.signer_priv_key}
aes_key - AES key as CryptoKey for encrypting the signature
nonce - base64url encoded uint8Array as initialization vector for AES
string_to_be_signed - encodable string
```

}
> 
> Signs the data and then encrypts it with the cipher.
> 
> **Returns**: A base64enconding of a Uint8Array containing a AES encrypted signature of the data.

**Use case:**

```
async function afoo() {
	let priv_keys = await galactic_user_starter_keys("signer") 
	let aes_key = await gen_cipher_key()
	let nonce = gen_nonce()
	//
	let string_to_be_signed = "this quick brown fox once again jumped over a fence for unknown reasons."
	//
	let hidden_sig = await protect_hash(priv_keys,aes_key,nonce,string_to_be_signed)
	...
}
```


[**contents**](#method-list)

------------------------------------------------------------------------


<a name="verify_protected" > </a>

* **verify\_protected**

>  **Parameters** {
> 
```
string_that_was_signed - (just the string as is)
encrypted_sig - the signature returned by protect_hash
pub_keys - An object containing public keys {pub_keys.signer_pk_str}
aes_key - aes key as CryptoKey
nonce - base64url encoded uint8Array
```
}
> 
> Decrypts the encrypted signature and then pass it to to **verify** to see if the caller can match the keys. 
> 
> **Returns**: True if the signature successfully passes verification, false otherwise.

**Use case:**

```
async function afoo() {
	let pub_keys = await retrieve_signer_public_key("signer") // a storage method
	let aes_key = await retrieve_the_aes_key_or_derive_it()
	let nonce = await retrieve_the_nonce_that_was_used()
	//
	let string_to_be_signed = "this quick brown fox once again jumped over a fence for unknown reasons."
	//
	let really = await verify_protected(priv_keys,aes_key,nonce,string_to_be_signed)
	if ( really ) {
		"OK
	} else {
		"NOT OK"
	}
	...
}
```



[**contents**](#method-list)

------------------------------------------------------------------------

<a name="unwrapped_aes_key" > </a>

* **unwrapped\_aes\_key**

>  **Parameters** {
> 
```
wrapped_aes - as a buffer containing a jwk formatted key
unwrapper_key - as a buffer the result of importing the key
```
}
> 
> Unwraps a AES key that has been previously wrapped using an RSA-OAEP wrapper key. The key that unwraps, `unwrapper_key`, is one part of the public/private key pair. The unwrapping key has been construted with these parameters:
> 
> ```
>	name: "RSA-OAEP",
>	modulusLength: 4096, //can be 1024, 2048, or 4096
>	publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
>	hash: { name: "SHA-256" }
> ```
> 
> The `wrapped_aes` is passed in JWK format. 
> 
> **Returns**: The AES key as a CryptoKey.

**Use case:**

```
async function afoo() {
	let JWK_wrapped_AES = await fetch_wrapped_key() // some db function
	let wrapper_key = await fetch_wrapper_key() // some db function
	let imported_key = import(wrapper_key) // use crytpo.subtle.import
	let aes_key = await unwrapped_aes_key(JWK_wrapped_AES,imported_key)
	// aes key is a Crypto Key for use in decipher, encipher
}
```


[**contents**](#method-list)

------------------------------------------------------------------------


<a name="derive_aes_key" > </a>

* **derive\_aes\_key**

>  **Parameters** {
> 
```
remote_pub_key_buffer - as a buffer containing a ECDH key previoulsy imported
local_private_key - as a buffer the result of importing the local ECDH key
```
}
> 
> Derives as AES key: AES-CBC 256. Uses the ECDH keys already in their buffer format.
> 
> **Returns**: aes_key as a CryptoKey structure (see crypto.subtle.generateKey) with ***encrypt*** and ***decrypt*** permissions.

**Use case:**

```
async function afoo() {
	let remote_key = await transfered_imported_buffer()
	let local_key = await retrieved_imported_keys()
	let aes_key = derive_aes_key(remote_key,local_key)
	...
}
```


[**contents**](#method-list)

------------------------------------------------------------------------


<a name="key_wrapper" > </a>


```
/*
// key_wrapper
// Parameters:
//        -- key_to_wrap  as Cryptokey
//        -- pub_wrapper_key :  the public wrapper key (for instance a receiver key) as jwk in JSON parseable string
// Returns: 
*/
```



* **key\_wrapper**

>  **Parameters** {
> 
```
key_to_wrap - as CryptoKey
pub_wrapper_key - a string including the public wrapper key (for instance a receiver key) as jwk in JSON format to be passed to JSON.parse
```
}
> 
> Wraps a CryptoKey object. Takes in the wrapper key as a JSON JWK string. Parses the string to an object, and then imports the JWK to the public wrapper key. Wraps the key to be wrapped and then base64 encodes the buffer returned from wrapping.
> 
> **Returns**: the wrapped key in a base64url string.

**Use case:**

```
async function afoo() {
	let key_to_wrap = await my_aes_key()
	let pub_wrapper_key = await retrieve_public_key_from_unwrapper()
	let wrapped_key_str = await key_wrapper(key_to_wrap,pub_wrapper_key)
	...
}
```



[**contents**](#method-list)

------------------------------------------------------------------------


<a name="key_unwrapper" > </a>

* **key\_unwrapper**

>  **Parameters** {
> 
```
wrapped_key - base64url encoded uint8array for passing to unwrapped_aes_key
piv_wrapper_key - a string including the private wrapper key (for instance a receiver key) as jwk in JSON format to be passed to JSON.parse
```
}
> 
> Unwraps a CryptoKey object. Assuming a remote partner has sent a key to the user program which stores a private key part of a public/private key pair made for key wrapping and unwrapping.
> 
> **Returns**: the unwrapped key as a CryptoKey

**Use case:**

```
async function afoo() {
	let wrapped_key = await sent_to_me_from_partner()
	let priv_wrapper_key = await retrieve_private_key_from_local_db()
	let useful_aes_key = await key_unwrapper(wrapped_key,piv_wrapper_key)
	...
}
```



[**contents**](#method-list)

------------------------------------------------------------------------

<a name="derive_key" > </a>

* **derive\_key**

>  **Parameters** {
> 
```
sender_public_key - base64 encoded buffer of a ECDH public key with derivation privileges
piv_axiom_key - the private key (for instance a sender key) as a JSON.parseable string representing jwk derivation privileges
```
}
> 
> Derives a CryptoKey object representing **AES-CBC**, 256. Converts the base64 buffer to a Uint8Array. Parses (JSON.parse) the string representation of the JKW formatted object containing the private key (local) as the derivation partner. Imports the JWK and then calls the derivation methods.
> 
> **Returns**: AES-CBC, 256 key as a CryptoKey structure (see crypto.subtle.generateKey) with ***encrypt*** and ***decrypt*** permissions

**Use case:**

```
async function afoo() {
	let derviaton_key = await sent_to_me_from_partner()
	let priv_derivation_key = await retrieve_private_key_from_local_db()
	let useful_aes_key = await derive_key(derviaton_key, priv_derivation_key)
	...
}
```


[**contents**](#method-list)

------------------------------------------------------------------------

<a name="aes_to_str" > </a>

* **aes\_to\_str**

>  **Parameters** {
> 
```
aes_key - as CryptoKey
transport_type - can be "jwk" or "raw"
```
}
> 
> Calls the export method on the key and then formats it as a string.
> 
> **Returns**: a string -> the exported key JSON.stringify of 'jwk' ||  base64url Uint8Array if 'raw'

**Use case:**

```
async function afoo() {
	let my_aes_key = fetch_my_aes_key_from_db() // or derive it or gen, etc.
	let key_str = await aes_to_str(my_aes_key,"jwk")
	console.log(key_str)
	...
}
```


[**contents**](#method-list)

------------------------------------------------------------------------

<a name="ecdh_to_str" > </a>

* **ecdh\_to\_str**

>  **Parameters** {
> 
```
ecdh_key - as CryptoKey
transport_type - can be "jwk" or "raw"
```
}
> 
> Calls the export method on the key and then formats it as a string. 
> If the jwk option is used, set key_ops to "deriveKey", enabling import as a derived key on a remote.
> 
> **Returns**: a string -> the exported key JSON.stringify of 'jwk' ||  base64url Uint8Array if 'raw'

**Use case:**

```
async function afoo() {
	let my_ecdh_key = fetch_my_public_ecdh_key_from_db() // or derive it or gen, etc.
	let key_str = await ecdh_to_str(my_aes_key,"jwk")
	console.log(key_str)
	...
}
```



[**contents**](#method-list)

------------------------------------------------------------------------


<a name="importAESKey" > </a>

* **importAESKey**

>  **Parameters** {
> 
```
rawKey --  This is an array buffer containing a key or it may be a JWK Object
transport_type :  can be "jwk" or "raw"
```
}
>
> Import an AES secret key from an ArrayBuffer containing the raw bytes or from JWK.
  Takes an ArrayBuffer containing the bytes or JWK object
> Calls the import method on the raw key and turns it into a CrypoKey eventually. Imports the key as a key with ***encrypt*** and ***decrypt*** privileges.
> 
> **Returns**: A promise that resolves to a CryptoKey.

**Use case:**

```
async function afoo() {
	let my_aes_key = await importAESKey(raw_key,"jwk")
	...
}
```


[**contents**](#method-list)

------------------------------------------------------------------------


<a name="importECDHKey" > </a>

* **importECDHKey**

>  **Parameters** {
> 
```
rawKey --  This is an array buffer containing a key or it may be a JWK Object
transport_type :  can be "jwk" or "raw"
```
}
>

> 
> Calls the import method on the raw key or JWK object and then turns it into a CryptoKey eventually. 
> If the jwk option is used, sets key_ops to "deriveKey", enabling import as a key with ***derivation*** privileges.
> 
> **Returns**: A promise that resolves to a CryptoKey.


[**contents**](#method-list)

------------------------------------------------------------------------

<a name="aes_from_str" > </a>


* **aes\_from\_str**

>  **Parameters** {
> 
```
aes_key_str - the exported key for JSON.stringify if 'jwk' or base64 if 'raw'
transport_type - can be "jwk" or "raw"
```
}
> 
> Calls the imprort method on the key previously formatted as a string.
> 
> **Returns**: the aes_key as a CryptoKey resulting from importing the key

**Use case:**

```
async function afoo() {
	let my_aes_k my_aes_key_str = await receive_my_aes_key()
	let aes_key = await str_to_aes(my_aes_key_str,"jwk")
	...
}
```


[**contents**](#method-list)

------------------------------------------------------------------------


<a name="key_signer" > </a>

* **key\_signer**

>  **Parameters** {
> 
```
data_to_sign - as a string that will be passed to a TextEncoder
priv_signer_key - the private key (for instance a sender key)
					  for signing  passed as a string that can be
					  JSON.parserd into a jwk format
```
}
> 
> Calls the imprort method on the key previously formatted as a string.
> 
> **Returns**: a base64url string containing the signature

**Use case:**

```
async function afoo() {
	let data_to_sign = "The quick brown fox has had just about enough of this jumping over fences thing."
	let priv_signer_key = await fetch_my_priv_ecdsa_string()
	let aes_key = await key_signer(data_to_sign,priv_signer_key)
	...
}
```


[**contents**](#method-list)

------------------------------------------------------------------------


<a name="verifier" > </a>


* **verifier**

>  **Parameters** {
> 
```
was_signed_data - as a string that was originially passed to key_signer
signature - the a base64url string containing the signature
signer_pub_key -  the public key (for instance a sender key) for
                  verification passed as a string that can be
                  JSON.parsed into a jwk formatß
```
}
> 
> Transforms inputs into data types that can be used by verify. 
> 
> **Returns**: true if the signature passes the test

**Use case:**

```
async function afoo() {
	let signature = await signture_from_sender()
	let was_signed_data = "The quick brown fox has had just about enough of this jumping over fences thing."
	let signer_pub_key = await fetch_public_ecdsa_string()
	
	let aes_key = await verifier(was_signed_data, signature, signer_pub_key)
	...
}
```



[**contents**](#method-list)

------------------------------------------------------------------------



<a name="encipher_message" > </a>


* **encipher\_message**

>  **Parameters** {
> 
```
was_signed_data - as a string that was originially passed to key_signer
signature - the a base64url string containing the signature
signer_pub_key -  the public key (for instance a sender key) for
                  verification passed as a string that can be
                  JSON.parsed into a jwk formatß
```
}
> 
> Transforms inputs into data types that can be used by verify. 
> 
> **Returns**: true if the signature passes the test

**Use case:**

```
async function afoo() {
	let signature = await signture_from_sender()
	let was_signed_data = "The quick brown fox has had just about enough of this jumping over fences thing."
	let signer_pub_key = await fetch_public_ecdsa_string()
	
	let aes_key = await verifier(was_signed_data, signature, signer_pub_key)
	...
}
```





[**contents**](#method-list)

------------------------------------------------------------------------

<a name="derived_encipher_message" > </a>

* **derived\_encipher\_message**

>  **Parameters** {
> 
```
message - a text string
remote_public_ky - as CryptoKey
local_private_ky :  as CryptoKey
nonce : as a string storing a buffer base64url
```
}
> 
> Derives an AES key and then uses it to encipher the message. 
> 
> **Returns**: A base64url encoded string of the encrypted message.

**Use case:**

```
async function afoo() {
	//
	let text = "A quicker brown fox avoided the fence altogether"
	let remote_public_ky = await for_a_key_from_partner()
	let local_private_ky = awat fetch_my_private_ecdh_key()
	let nonce = gen_nonce()
	let enciphered = await derived_encipher_message(text,remote_public_ky, local_private_ky,nonce)
	...
}
```


[**contents**](#method-list)

------------------------------------------------------------------------


<a name="decipher_message" > </a>

* **decipher\_message**

>  **Parameters** {
> 
```
message - base64url encoded, encrypted string returned from encipher
wrapped_key - wrapped AES key passed as a string in base64url format
priv_key - the private key witgh unwrap privileges passed as a string that can be JSON.parsed into a jwk format object
nonce - as a string storing a buffer base64url
```
}
> 
> Decrypts a message given the transport version of keys.
> 
> **Returns**: The clear string or false if it cannot be decrypted

**Use case:**

```
async function afoo() {
	//
	let [wrapped_key, nonce] = await get_key_from_partner()
	// later
	let message = await recieve_encrypted_message()
	let priv_key = await fetch_my_private_key()
	let clear_text = await decipher_message(message,wrapped_key,priv_key,nonce)
		...
}
```



[**contents**](#method-list)

------------------------------------------------------------------------



<a name="derived_decipher_message" > </a>


* **derived\_decipher\_message**

>  **Parameters** {
> 
```
message - base64url encoded, encrypted string returned from encipher
remote_public - a pubic key for ECDH P-384 key encryption passed as a string that can be JSON.parsed
priv_key - the private key witgh unwrap privileges passed as a string that can be JSON.parsed into a jwk format object
nonce - as a string storing a buffer base64url
```
}
> 
> Decrypts a message given the transport version of keys.
> 
> **Returns**: The clear string or false if it cannot be decrypted

**Use case:**

```
async function afoo() {
	//
	let [wrapped_key, nonce] = await get_key_from_partner()
	// later
	let message = await recieve_encrypted_message()
	let priv_key = await fetch_my_private_key()
	let clear_text = await derived_decipher_message(message,wrapped_key,priv_key,nonce)
		...
}
```


[**contents**](#method-list)

------------------------------------------------------------------------


<a name="gen_public_key" > </a>


```

/*
// gen_public_key
// Parameters:
//            -- info - an info object (javascript object) which gain fields info.public_key and info.signer_public_key
//                      optionally provides a field info.biometric, which will be signed and signature will be put into this field
//            -- store_info - a method taking two parameters (info,privates)  privates is the Object created in this method
// 
*/
```


[**contents**](#method-list)

------------------------------------------------------------------------







## source code and implementation notes: node.js and browser

The code for the browser and node.js is generated by a process that places them in different directories.

The package.json file has a module and an main field for the two flavors of package loading.

### > typescript

A typescript interface has been generated


### > package directories

The browser modules begin in the **clients** directory. And, the node.js versions begin in the **lib** directory.

A rollup.config.js file is supplied in these packages. 

