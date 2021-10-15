import { atobUrlSafe, btoaUrlSafe } from "../../../../../oidc-tester/assets/common/modules/base64url.js";
import { toUint8Array} from "./WebAuthnDecoder.js";

/**
 * base64url encode bytes 
 * @param {ArrayBuffer|Uint8Array} array - array of bytes
 * @returns {string} - base64url encoded string
 */
function encodeArray(array) {
    array = toUint8Array(array);
    return btoaUrlSafe(Array.from(array, t => String.fromCharCode(t)).join(""));
}

/**
 * base64url decode string
 * @param {string} value - base64url encoded string
 * @returns {Uint8Array} - array of bytes
 */
 function decodeArray(value) {
    if(typeof value !== "string") {
        throw new Error("invalid argument");
    }
    return Uint8Array.from(atobUrlSafe(value), t => t.charCodeAt(0));
}

export { encodeArray, decodeArray, atobUrlSafe, btoaUrlSafe };
