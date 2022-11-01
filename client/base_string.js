//>--

// 
/**
 * @param {Array.<number>}  arrayOfBytes - A string param.
 * @returns {string} - hex string
 */
export function hex_fromArrayOfBytes(arrayOfBytes) {
    const hexstr = arrayOfBytes.map(b => b.toString(16).padStart(2, '0')).join('');
    return(hexstr)
}
//--<

//>--
/**
 * @param {Uint8Array}  byteArray - A string param.
 * @returns {string} - hex string
 */
export function hex_fromTypedArray(byteArray){
    let arrayOfBytes = Array.from(byteArray)
    return(hex_fromArrayOfBytes(arrayOfBytes))
}
//--<


//>--
/**
 * @param {number []}  byteArray - A string param.
 * @returns {string} - hex string
 */
export function hex_fromByteArray(byteArray){
    return hex_fromTypedArray(ArrayOfBytes_toByteArray(byteArray))
}
//--<


//>--
/**
 * @param {string}  hexString - A string param.
 * @returns {number []} - hex string
 */
export function hex_toArrayOfBytes(hexString) {
    let result = [];
    for ( let i = 0; i < hexString.length; i += 2 ) {
      result.push(parseInt(hexString.substring(i, 2), 16));
    }
    return result;
}
//--<

//>--
/**
 * @param {number []}  arrayOfBytes - A string param.
 * @returns {Uint8Array} - hex string
 */
export function ArrayOfBytes_toByteArray(arrayOfBytes) {
    let byteArray = new Uint8Array(arrayOfBytes)
    return(byteArray)
}
//--<

//>--
/**
 * @param {string}  hexstr - A string param.
 * @returns {Uint8Array} - hex string
 */
export function hex_toByteArray(hexstr) {
    let aob = hex_toArrayOfBytes(hexstr)
    return ArrayOfBytes_toByteArray(aob)
}
//--<

//>--

export function bufferToArrayBufferCycle(buffer) {
  var ab = new ArrayBuffer(buffer.length);
  var view = new Uint8Array(ab);
  for (var i = 0; i < buffer.length; ++i) {
      view[i] = buffer[i];
  }
  return ab;
}
//--<

/**
 * @param {number [] | Uint8Array}  bytes - A string param.
 * @returns {string} - hex string
 */
export function string_from_buffer(bytes) {
	let s = ""
	let n = bytes.length
	for ( let i = 0; i < n; i++ ) {
		let c_code = bytes[i]
		s += String.fromCharCode(c_code)
	}
	return s
}

/**
 * @param {string}  number_els - A string param.
 * @returns {Uint8Array} - hex string
 */
export function buffer_from_cvs_array(number_els) {
	let els = number_els.split(',').map(el => parseInt(el))
	let buf = new Uint8Array(els)
	return buf
}

/**
 * @param {string}  number_els - base64 encoded string of comma delimited numbers
 * @returns {Uint8Array} - hex string
 */
export function buffer_from_b64_csv(b64_number_els) {
	let numbers = atob(b64_number_els)
	return buffer_from_cvs_array(numbers)
}
