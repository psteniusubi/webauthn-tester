# WebAuthn API Tester

This is a browser based WebAuthn API Tester. Launch by navigating to following page

https://psteniusubi.github.io/webauthn-tester/

The [Working with FIDO and the WebAuthn API](https://www.ubisecure.com/api/fido-webauthn-api/) article covers the WebAuthn API and use cases in more detail.

## Requirements

You need a WebAuthn authenticator to use the tool. Windows Hello, Android Fingerprint or Apple Touch ID are examples of very common authenticators.

If you are using Windows 10 or later, then you only need to [set up Windows Hello](https://support.microsoft.com/en-us/help/4028017/windows-learn-about-windows-hello-and-set-it-up).

# Instructions

## Register (Create Credential)

https://psteniusubi.github.io/webauthn-tester/create.html

This app stores credentials in local storage of your browser.

## Authenticate (Get Credential)

https://psteniusubi.github.io/webauthn-tester/get.html

## Edit Credentials

https://psteniusubi.github.io/webauthn-tester/edit.html

This page lets you copy and paste portable credentials across browsers and devices.

# Decoding WebAuthn data types

## Rendering notes

The tools renders JavaScript objects and dictionaries as JSON, where Array and Buffer data types are presented as Base64Url encoded strings.

For example, the "challenge" property is defined as

```
challenge, of type BufferSource
```

the tool will render this as

```
"challenge": "SABWyoy28rCoCVR3DTDuLyUQb2nXg_wPiZ5c6O2DV0U"
```

Rendering is implemented with `JSON.stringify` and a replacer function. For example

```javascript
import { encodeArray } from "./base64.js";

export function replacer(k, v) {
    if (v instanceof ArrayBuffer) {
        return encodeArray(v);
    }
    if (v instanceof Uint8Array) {
        return encodeArray(v);
    }
    return v;
}

JSON.stringify(publicKeyCredential, replacer, 2);
```

## AuthenticatorAttestationResponse

### <a name="clientDataJSON">clientDataJSON</a>

https://w3c.github.io/webauthn/#dom-authenticatorresponse-clientdatajson

clientDataJSON is a JSON object serialized to bytes. The code below assumes only ASCII characters.

```javascript
export function decodeClientDataJSON(data) {
    data = toUint8Array(data);
    return JSON.parse(Array.from(data, t => String.fromCharCode(t)).join(""))
}
```

### attestationObject

https://w3c.github.io/webauthn/#dom-authenticatorattestationresponse-attestationobject

attestationObject is CBOR encoded. The code below uses CborSimpleDecoder.

```javascript
export function decodeAttestationObject(data) {
    data = toArrayBuffer(data);
    return CborSimpleDecoder.readObject(new BinaryReader(data));
}
```

### <a name="authData">authData</a>

https://w3c.github.io/webauthn/#sctn-authenticator-data

Authenticator data (authData and authenticatorData) is a compact binary encoding.

```javascript
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
```

### credentialPublicKey

https://w3c.github.io/webauthn/#credentialpublickey

https://w3c.github.io/webauthn/#sctn-encoded-credPubKey-examples

credentialPublicKey is COSE encoded. This code translates COSE to JWK, a more human readable format. 

This is not a general purpose COSE translator. Only WebAuthn algorithm identifiers are recognized.

```javascript
export function coseToJwk(data) {
	let alg, crv;
	switch (data[1]) {
		case 2: // EC
			switch (data[3]) {
				case -7: alg = "ES256"; break;
				default: throw new Error("invalid argument");
			}
			switch (data[-1]) {
				case 1: crv = "P-256"; break;
				default: throw new Error("invalid argument");
			}
			if (!data[-2] || !data[-3]) throw new Error("invalid argument");
			return {
				"kty": "EC",
				"alg": alg,
				"crv": crv,
				"x": encodeArray(data[-2]),
				"y": encodeArray(data[-3]),
			};
		case 3: // RSA
			switch (data[3]) {
				case -37: alg = "PS256"; break;
				case -257: alg = "RS256"; break;
				default: throw new Error("invalid argument");
			}
			if (!data[-1] || !data[-2]) throw new Error("invalid argument");
			return {
				"kty": "RSA",
				"alg": alg,
				"n": encodeArray(data[-1]),
				"e": encodeArray(data[-2]),
			};
		default: throw new Error("invalid argument");
	}
}
```

## AuthenticatorAssertionResponse

### clientDataJSON

See [clientDataJSON](#clientDataJSON)

### authenticatorData

See [authData](#authData)

### signature

https://w3c.github.io/webauthn/#sctn-op-get-assertion

The R and S components of the EC signature of WebAuthn are ASN.1 encoded. The code below translates to WebCrypto compatible signature format. 

This implementation only supports 256 bit R and S components of ES256 algorithm.

```javascript
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
```

### verifyAssertionSignature 

https://w3c.github.io/webauthn/#assertion-signature

https://w3c.github.io/webauthn/#sctn-op-get-assertion

To verify assertion signature with WebCrypto the algorithm identifiers, signature value and public key need to be translated into WebCrypto compatible format.

The signature is calculated over `authenticatorData || sha256(clientDataJSON)`.

Note that WebCrypto in Microsoft Edge does not support EC signature algorithm. EC is commonly used with cross-platform (USB connected) authenticators.

```javascript
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
```
