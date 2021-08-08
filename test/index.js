const test = require('ava');
let cwraps = require('../lib/crypto-wraps')
let hashit = require('../lib/crypto-hash')

test('crypto-hash', t => {

    t.true(true)

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

    console.log(nonce)
    console.log(key)

    t.is(key.type,'secret')
    t.true(key.extractable)
    t.is(key.algorithm.name,'AES-CBC')
    t.is(key.algorithm.length,256)
    t.is(key.usages[0],'encrypt')
    t.is(key.usages[1],'decrypt')
    //
    
    t.pass("this is a test")
})