import { toArrayBuffer, BinaryReader } from "./WebAuthnDecoder.js";
import { importJWK, sha256, getAlgorithm } from "./Crypto.js";

/**
 * Decode assertion signature to WebCrypto format
 * @see https://w3c.github.io/webauthn/#assertion-signature
 * @param {object} publicKey - JWK
 * @param {ArrayBuffer|Uint8Array} signature - WebAuthn assertion signature
 * @returns {Uint8Array}
 */
export function decodeSignature(publicKey, signature) {
    signature = toArrayBuffer(signature);
    const reader = new BinaryReader(signature);
    if (publicKey.kty === "EC") {
        /*
            0x30|b1|0x02|b2|r|0x02|b3|s
            b1 = Length of remaining data
            b2 = Length of r
            b3 = Length of s 
         */
        if (reader.readUInt8() != 0x30) throw new Error("invalid argument");
        const b1 = reader.readUInt8();
        if (reader.readUInt8() != 0x02) throw new Error("invalid argument");
        let b2 = reader.readUInt8();
        if (b2 > 32) {
            b2--;
            reader.readUInt8();
        }
        const r = reader.readBytes(b2);
        if (reader.readUInt8() != 0x02) throw new Error("invalid argument");
        let b3 = reader.readUInt8();
        if (b3 > 32) {
            b3--;
            reader.readUInt8();
        }
        const s = reader.readBytes(b3);
        const rs = new Uint8Array(64);
        rs.set(new Uint8Array(r), 0);
        rs.set(new Uint8Array(s), 32);
        return rs;
    } else {
        return signature;
    }
}

/**
 * Invokes crypto.subtle.verify to verify assertion signature
 * @see https://w3c.github.io/webauthn/#iface-pkcredential
 * @see https://w3c.github.io/webauthn/#authenticatorassertionresponse
 * @see https://w3c.github.io/webauthn/#assertion-signature
 * @see https://w3c.github.io/webcrypto/#SubtleCrypto-method-verify
 * @param {PublicKeyCredential} publicKeyCredential - WebAuthn Credential
 * @param {AuthenticatorAssertionResponse} publicKeyCredential.response 
 * @param {object} publicKey - JWK
 * @returns {Promise<boolean>} - true
 */
export async function verifyAssertionSignature(publicKeyCredential, publicKey) {

    const alg = publicKey.alg ?? "S256";

    const key = await importJWK(publicKey, alg);

    const hash = await sha256(publicKeyCredential.response.clientDataJSON);

    const signed = new Uint8Array(publicKeyCredential.response.authenticatorData.byteLength + hash.byteLength);
    signed.set(new Uint8Array(publicKeyCredential.response.authenticatorData), 0);
    signed.set(new Uint8Array(hash), publicKeyCredential.response.authenticatorData.byteLength);

    const signature = decodeSignature(publicKey, publicKeyCredential.response.signature);

    const verify = await crypto.subtle.verify(getAlgorithm(publicKey, alg), key, signature, signed);

    return verify;
}
