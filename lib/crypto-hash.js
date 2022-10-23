//

// buffer_from_cvs_array
function buffer_from_cvs_array(number_els) {
	let els = number_els.split(',').map(el => parseInt(el))
	let buf = new Uint8Array(els)
	return buf
}

module.exports.buffer_from_cvs_array = buffer_from_cvs_array
// <<

// buffer_from_b64_csv

function buffer_from_b64_csv(b64_number_els) {
    let numbers =from_base64(b64_number_els)
	return buffer_from_cvs_array(numbers)
}

module.exports.buffer_from_b64_csv = buffer_from_b64_csv
// <<


// to_base64

function to_base64(text) {
    const buf = Buffer.from(text, 'utf-8');
    return buf.toString('base64url')
}

module.exports.to_base64 = to_base64
// <<


// from_base64

function from_base64(base64text) {
    let b = Buffer.from(base64text,'base64url')
    const bytesAsText = b.toString('utf-8');
    return bytesAsText
}

module.exports.from_base64 = from_base64
// <<


// from_base64_to_uint8array

function from_base64_to_uint8array(base64text) {
    let b = Buffer.from(base64text,'base64url')
    return b
}

module.exports.from_base64_to_uint8array = from_base64_to_uint8array
// <<


// to_base64_from_uint8array

function to_base64_from_uint8array(a_uint8Array) {
    let b = Buffer.from(a_uint8Array)
    return b.toString('base64url')
}

module.exports.to_base64_from_uint8array = to_base64_from_uint8array
// <<

