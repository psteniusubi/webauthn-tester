import { atobUrlSafe, btoaUrlSafe } from "../../../../../oidc-tester/assets/common/modules/base64url.js";

function encodeArray(array) {
    if(array instanceof ArrayBuffer) {
        array = new Uint8Array(array);
    }
    if(!(array instanceof Uint8Array)) {
        throw new Error("invalid argument");
    }
    return btoaUrlSafe(Array.from(array, t => String.fromCharCode(t)).join(""));
}

function decodeArray(value) {
    if(typeof value !== "string") {
        throw new Error("invalid argument");
    }
    return Uint8Array.from(atobUrlSafe(value), t => t.charCodeAt(0));
}

export { encodeArray, decodeArray, atobUrlSafe, btoaUrlSafe };
