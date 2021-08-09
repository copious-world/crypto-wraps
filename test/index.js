const test = require('ava');
let cwraps = require('../lib/crypto-wraps')
let hashit = require('../lib/crypto-hash');
const { sign } = require('crypto');

test('crypto-hash', t => {
    //
    t.true(true)
    //
    let b = hashit.buffer_from_cvs_array("1,2,3,4,5")
    t.is(b[0],1)
    t.is(b[4],5)
    t.is(b.length,5)
    //
    let b64 = hashit.to_base64("1,2,3,4,5")
    t.is(b64,"MSwyLDMsNCw1")
    let numstr = hashit.from_base64("MSwyLDMsNCw1")
    t.is(numstr,"1,2,3,4,5")
    //
    b = hashit.buffer_from_b64_csv("MSwyLDMsNCw1")
    t.is(b[0],1)
    t.is(b[4],5)
    t.is(b.length,5)
    //
    t.pass("this is a test")
})


test('crypto-wrap', async t => {
    let nonce = cwraps.gen_nonce()

    let key = await cwraps.gen_cipher_key()

    t.is(key.type,'secret')
    t.true(key.extractable)
    t.is(key.algorithm.name,'AES-CBC')
    t.is(key.algorithm.length,256)
    t.is(key.usages[0],'encrypt')
    t.is(key.usages[1],'decrypt')
    //

    let encodable = "this is a test 1234"
    let iv_nonce = hashit.from_base64_to_uint8array(nonce)
    let text = await cwraps.aes_encryptor(encodable,key,iv_nonce)
    text = await cwraps.aes_decipher_message(text,key,iv_nonce)
    t.is(text,encodable)

    let key_pack = await cwraps.galactic_user_starter_keys()

    t.false(key_pack.pk_str === undefined)
    t.false(key_pack.priv_key === undefined)
    t.false(key_pack.signer_pk_str === undefined)
    t.false(key_pack.signer_priv_key === undefined)
    //
    t.is(typeof key_pack.pk_str,"string")
    t.is(typeof key_pack.priv_key,"string")
    t.is(typeof key_pack.signer_pk_str,"string")
    t.is(typeof key_pack.signer_priv_key,"string")
    //
    try {
        let pk_str = JSON.parse(key_pack.pk_str)
        t.is(pk_str.key_ops[0],"wrapKey")
        t.is(pk_str.ext,true)
        t.is(pk_str.kty,"RSA")
        t.is(pk_str.alg,"RSA-OAEP-256")
    } catch(e) {
        t.fail("could not parse jwk package")
    }
    //
    try {
        let priv_key = JSON.parse(key_pack.priv_key)
        t.is(priv_key.key_ops[0],"unwrapKey")
        t.is(priv_key.ext,true)
        t.is(priv_key.kty,"RSA")
        t.is(priv_key.alg,"RSA-OAEP-256")
    } catch(e) {
        t.fail("could not parse jwk package")
    }
    //
    try {
        let signer_pk_str = JSON.parse(key_pack.signer_pk_str)
        t.is(signer_pk_str.key_ops[0],"verify")
        t.is(signer_pk_str.ext,true)
        t.is(signer_pk_str.kty,"EC")
        t.is(signer_pk_str.crv,"P-384")
    } catch(e) {
        t.fail("could not parse jwk package")
    }    
    //
    try {
        let signer_priv_key = JSON.parse(key_pack.signer_priv_key)
        t.is(signer_priv_key.key_ops[0],"sign")
        t.is(signer_priv_key.ext,true)
        t.is(signer_priv_key.kty,"EC")
        t.is(signer_priv_key.crv,"P-384")
    } catch(e) {
        t.fail("could not parse jwk package")
    }

    /// 
    let string_to_be_signed = "Testing the signer part of a string signer"
    let storable_key = await cwraps.aes_to_str(key) 
	let priv_keys = {		// private keys will be stored locally, and may offloadded from the browser at the user's discretion.
		'priv_key' : key_pack.priv_key,
		'signer_priv_key' : key_pack.signer_priv_key,
		'signature_protect' : {
			"key" : storable_key,
			"nonce" : nonce
		}
	}

    let signature = await cwraps.key_signer(string_to_be_signed,key_pack.signer_priv_key)
    let verified = await cwraps.verifier(string_to_be_signed,signature,key_pack.signer_pk_str)
    t.true(verified)

    let encrypted_sig = await cwraps.protect_hash(priv_keys,key,nonce,string_to_be_signed)
    verified = await cwraps.verifier(string_to_be_signed,encrypted_sig,key_pack.signer_pk_str)
    t.false(verified)
    verified = await cwraps.verify_protected(string_to_be_signed,encrypted_sig,key_pack,key,nonce)
    t.true(verified)
    //
    let ky_str = await cwraps.aes_to_str(key,"raw") 
    let aes_key = await cwraps.aes_from_str(ky_str,"raw")

    t.is(aes_key.type,key.type)
    t.is(aes_key.extractable,key.extractable)
    t.is(aes_key.algorithm.name,key.algorithm.name)
    t.is(aes_key.algorithm.length,key.algorithm.length)
    t.is(aes_key.usages[0],key.usages[0])
    t.is(aes_key.usages[1],key.usages[1])


    ky_str = await cwraps.aes_to_str(key,"jwk") 
    t.true(ky_str.indexOf('"alg":"A256CBC"') > 0)
    aes_key = await cwraps.aes_from_str(ky_str,"jwk")


    t.is(aes_key.type,key.type)
    t.is(aes_key.extractable,key.extractable)
    t.is(aes_key.algorithm.name,key.algorithm.name)
    t.is(aes_key.algorithm.length,key.algorithm.length)
    t.is(aes_key.usages[0],key.usages[0])
    t.is(aes_key.usages[1],key.usages[1])
    //

    let again_text = "Finally the last test again until the next last test."
    let again_cipher_text = await cwraps.encipher_message(again_text,aes_key,nonce)
    let wrapped_key = await cwraps.key_wrapper(aes_key,key_pack.pk_str)
    let again_decipher_text =  await cwraps.decipher_message(again_cipher_text,wrapped_key,key_pack.priv_key,nonce)

    t.is(again_text,again_decipher_text)
    //
    t.pass("this is a test")
})