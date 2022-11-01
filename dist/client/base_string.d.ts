/**
 * @param {Array.<number>}  arrayOfBytes - A string param.
 * @returns {string} - hex string
 */
export function hex_fromArrayOfBytes(arrayOfBytes: Array<number>): string;
/**
 * @param {Uint8Array}  byteArray - A string param.
 * @returns {string} - hex string
 */
export function hex_fromTypedArray(byteArray: Uint8Array): string;
/**
 * @param {number []}  byteArray - A string param.
 * @returns {string} - hex string
 */
export function hex_fromByteArray(byteArray: number[]): string;
/**
 * @param {string}  hexString - A string param.
 * @returns {number []} - hex string
 */
export function hex_toArrayOfBytes(hexString: string): number[];
/**
 * @param {number []}  arrayOfBytes - A string param.
 * @returns {Uint8Array} - hex string
 */
export function ArrayOfBytes_toByteArray(arrayOfBytes: number[]): Uint8Array;
/**
 * @param {string}  hexstr - A string param.
 * @returns {Uint8Array} - hex string
 */
export function hex_toByteArray(hexstr: string): Uint8Array;
export function bufferToArrayBufferCycle(buffer: any): ArrayBuffer;
/**
 * @param {number [] | Uint8Array}  bytes - A string param.
 * @returns {string} - hex string
 */
export function string_from_buffer(bytes: number[] | Uint8Array): string;
/**
 * @param {string}  number_els - A string param.
 * @returns {Uint8Array} - hex string
 */
export function buffer_from_cvs_array(number_els: string): Uint8Array;
export function buffer_from_b64_csv(b64_number_els: any): Uint8Array;
//# sourceMappingURL=base_string.d.ts.map