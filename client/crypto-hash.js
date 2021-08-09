//
import * as base64 from "../modules/base64.js";

if ( window.g_crypto === undefined ) {
    window.g_crypto = window.crypto ? window.crypto.subtle : null
    if ( g_crypto === null  ) {
      alert("No cryptography support in this browser. To claim ownership of assets, please use another browser.")
    }
    
}


export function buffer_from_cvs_array(number_els) {
	let els = number_els.split(',').map(el => parseInt(el))
	let buf = new Uint8Array(els)
	return buf
}

export function buffer_from_b64_csv(b64_number_els) {
	let numbers = atob(b64_number_els)
	return buffer_from_cvs_array(numbers)
}
// ---- ---- ---- ---- ---- ---- ---- ---- ---- ----


async function do_hash_buffer(text) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const hash = await g_crypto.digest('SHA-256', data);
    return hash
}

export async function do_hash(text) {
    let buffer = await do_hash_buffer(text)
    const hashArray = Array.from(new Uint8Array(buffer));
    return base64.bytesToBase64(hashArray)
}

export function from_hash(base64text) {
    let bytes = base64.base64ToBytes(base64text)
    return bytes
}

export function to_base64(text) {
    return base64.base64encode(text)
}

export function from_base64(base64text) {
    let bytesAsText = base64.base64decode(base64text)
    return bytesAsText
}



export function from_base64_to_uint8array(base64text) {
    while ( base64text.length %4 ) base64text += '='
    return base64.base64ToBytes(base64text)
}

export function to_base64_from_uint8array(a_uint8Array) {
    let b = base64.bytesToBase64(a_uint8Array)
    b = b.replace(/\=/g,'')
    return b
}


// ----------------------------  allow certain methods to be global (up to the application to call)
export function windowize_crypto_hash() {
    window.do_hash = do_hash
}

