//
function buffer_from_cvs_array(number_els) {
	let els = number_els.split(',').map(el => parseInt(el))
	let buf = new Uint8Array(els)
	return buf
}

module.exports.buffer_from_cvs_array = buffer_from_cvs_array

function buffer_from_b64_csv(b64_number_els) {
    let buf = Buffer.from(b64_number_els,'base64url')
    let ua8 = new Uint8Array(buf.buffer,0,buf.length)
    let numbers = ua8.toString()
	return buffer_from_cvs_array(numbers)
}

module.exports.buffer_from_b64_csv = buffer_from_b64_csv

function to_base64(text) {
    const buf = Buffer.from(text, 'utf-8');
    return buf.toString('base64url')
}

module.exports.to_base64 = to_base64

function from_base64(base64text) {
    let b = Buffer.from(base64text,'base64url')
    const bytesAsText = b.toString('utf-8');
    return bytesAsText
}

module.exports.from_base64 = from_base64