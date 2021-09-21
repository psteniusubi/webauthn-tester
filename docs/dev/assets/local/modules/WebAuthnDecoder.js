import { CborSimpleDecoder, BinaryReader } from "../../../../../frontend/cbor/assets/local/modules/CborSimpleDecoder.js";
import * as WebAuthn from "./WebAuthnTypes.js";
import { coseToJwk } from "./Crypto.js";

export function toUint8Array(data) {
    if (data instanceof Uint8Array) {
        return data;
    }
    if (data instanceof ArrayBuffer) {
        return new Uint8Array(data);
    }
    throw new Error("invalid argument");
}

export function toArrayBuffer(data) {
    if (data instanceof Uint8Array) {
        return data.buffer;
    }
    if (data instanceof ArrayBuffer) {
        return data;
    }
    throw new Error("invalid argument");
}

export function toDataView(data) {
    if (data instanceof DataView) {
        return data;
    }
    if (data instanceof ArrayBuffer) {
        return new DataView(data);
    }
    if (data instanceof Uint8Array) {
        return new DataView(data);
    }
    throw new Error("invalid argument");
}

export function decodeClientDataJSON(data) {
    data = toUint8Array(data);
    return JSON.parse(Array.from(data, t => String.fromCharCode(t)).join(""))
}

export function decodeAttestationObject(data) {
    data = toArrayBuffer(data);
    return CborSimpleDecoder.readObject(new BinaryReader(data));
}

export function decodeAuthenticatorData(data) {
    data = toArrayBuffer(data);
    const reader = new BinaryReader(data);

    /**
     * https://w3c.github.io/webauthn/#sec-authenticator-data
     *
     * rpIdHash 32
     * flags 1
     *  bit 0 up
     *  bit 2 uv
     *  bit 6 at
     *  bit 7 ed
     * signCount 4
     * attestedCredentialData variable
     * extensions variable
     */
    const authenticatorData = new WebAuthn.AuthenticatorData();
    // rpIdHash
    authenticatorData.rpIdHash = reader.readBytes(32);
    // flags
    authenticatorData.flags = reader.readUInt8();
    // signCount
    authenticatorData.signCount = reader.readUInt32();

    // attestedCredentialData 
    if (authenticatorData.at) {
        /**
         * https://w3c.github.io/webauthn/#sec-attested-credential-data
         *
         * aaguid 16
         * credentialIdLength 2
         * credentialId L
         * credentialPublicKey variable
         */
        authenticatorData.attestedCredentialData = new WebAuthn.AttestedCredentialData();
        // aaguid
        authenticatorData.attestedCredentialData.aaguid = reader.readBytes(16);
        // credentialIdLength
        const credentialIdLength = reader.readUInt16();
        // credentialId
        authenticatorData.attestedCredentialData.credentialId = reader.readBytes(credentialIdLength);
        // credentialPublicKey
        const credentialPublicKey = CborSimpleDecoder.readObject(reader);
        authenticatorData.attestedCredentialData.credentialPublicKey = coseToJwk(credentialPublicKey);
    }

    // extensions
    if (authenticatorData.ed) {
        authenticatorData.extensions = reader.readBytes(reader.byteLength - reader.byteOffset - reader.readerOffset);
    }

    return authenticatorData;
}

export { coseToJwk, CborSimpleDecoder, BinaryReader };

export { verifyAssertionSignature } from "./Signature.js";
