# Web Authentication API Tester

https://psteniusubi.github.io/webauthn-tester/

## Requirements

You need a FIDO authenticator to use the tool. If you are using Windows 10 with 1809 update or later, then you only need to [set up Windows Hello](https://support.microsoft.com/en-us/help/4028017/windows-learn-about-windows-hello-and-set-it-up) as your FIDO authenticator and use Microsoft Edge to run the tool.

# Instructions

## Register (Create Credential)

https://psteniusubi.github.io/webauthn-tester/credential-create.html

## Authenticate (Get Credential)

https://psteniusubi.github.io/webauthn-tester/credential-get.html

## Edit Credentials

https://psteniusubi.github.io/webauthn-tester/credential-edit.html

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

Rendering is implemented with JSON.stringify and a replacer function. For example

```javascript
function replacer(k,v) {
	if(v && v.constructor === Uint8Array) {
		return encodeArray(v);
	}
	if(v && v.constructor === ArrayBuffer) {
		return encodeArray(v);
	}
	...
}

JSON.stringify(publicKeyCredential, replacer, 2);
```

## PublicKeyCredential

Extending replacer to display PublicKeyCredential and other WebAuthn data types

```javascript
function replacer(k,v) {
	...
	if(v && v.constructor === PublicKeyCredential) {
		return {
			id: v.id,
			type: v.type,
			rawId: v.rawId,
			response: v.response,
		};
	}
	if(v && v.constructor === AuthenticatorAttestationResponse) {
		return {
			clientDataJSON: v.clientDataJSON,
			attestationObject: v.attestationObject, 
		};
	}
	if(v && v.constructor === AuthenticatorAssertionResponse) {
		return {
			clientDataJSON: v.clientDataJSON,
			authenticatorData: v.authenticatorData, 
			signature: v.signature, 
			userHandle: v.userHandle, 
		};
	}
	...
	return v;
}
```

## AuthenticatorAttestationResponse

### <a name="clientDataJSON">clientDataJSON</a>

```javascript
/**
 * https://w3c.github.io/webauthn/#dom-authenticatorresponse-clientdatajson
 */
function decodeClientDataJSON(data) {
	return JSON.parse(Array.from(new Uint8Array(data), t => String.fromCharCode(t)).join(""))
}
```

### attestationObject

```javascript
/**
 * https://w3c.github.io/webauthn/#dom-authenticatorattestationresponse-attestationobject
 */
function decodeAttestationObject(data) {
	return CBOR.decode(data);
}
```

### <a name="authData">authData</a>

```javascript
/**
 * https://w3c.github.io/webauthn/#sec-authenticator-data
 */
function decodeAuthenticatorData(data) {
	if(data.constructor === Uint8Array) {
		data = data.buffer.slice(data.byteOffset, data.byteLength + data.byteOffset);
	}
	if(data.constructor !== ArrayBuffer) {
		throw "Invalid argument: " + data.constructor;
	}
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
	var view = new DataView(data);
	var offset = 0;
	var rpIdHash = view.buffer.slice(offset, offset + 32); offset += 32;
	var flags = view.getUint8(offset); offset += 1;
	var signCount = view.getUint32(offset, false); offset += 4;
	var authenticatorData = {
		rpIdHash: rpIdHash,
		flags: {
			value: flags,
			up: (flags & 0x01) != 0,
			uv: (flags & 0x04) != 0,
			at: (flags & 0x40) != 0,
			ed: (flags & 0x80) != 0,
		},
		signCount: signCount,
	};
	// attestedCredentialData 
	if(authenticatorData.flags.at) {
		/**
		 * https://w3c.github.io/webauthn/#sec-attested-credential-data
		 *
		 * aaguid  16
		 * credentialIdLength 2
		 * credentialId  L
		 * credentialPublicKey variable
		 */
		var aaguid = view.buffer.slice(offset, offset + 16); offset += 16;
		var credentialIdLength = view.getUint16(offset, false); offset += 2;
		var credentialId = view.buffer.slice(offset, offset + credentialIdLength); offset += credentialIdLength;
		var credentialPublicKey = view.buffer.slice(offset);
		authenticatorData.attestedCredentialData = {
			aaguid: aaguid,
			credentialId: credentialId,
			credentialPublicKey: credentialPublicKey,
		};
	}
	return authenticatorData;
}
```

### credentialPublicKey

```javascript
/**
 * https://w3c.github.io/webauthn/#credentialpublickey
 */
function decodeCredentialPublicKey(data) {
	var obj = CBOR.decode(data);
	return coseToJwk(obj);
}

/**
 * https://w3c.github.io/webauthn/#sctn-encoded-credPubKey-examples
 */
function coseToJwk(data) {
	var alg, crv;
	switch(data[1]) {		
		case 2: // EC
			switch(data[3]) {
				case -7: alg = "ES256"; break;
				default: throw "Invalid argument";
			}
			switch(data[-1]) {
				case 1: crv = "P-256"; break;
				default: throw "Invalid argument";
			}
			if(!data[-2] || !data[-3]) throw "Invalid argument";
			return {
				"kty":"EC",
				"alg":alg,
				"crv":crv,
				"x":encodeArray(data[-2]),
				"y":encodeArray(data[-3]),
			};
		case 3: // RSA
			switch(data[3]) {
				case -37: alg = "PS256"; break;
				case -257: alg = "RS256"; break;
				default: throw "Invalid argument";
			}
			if(!data[-1] || !data[-2]) throw "Invalid argument";
			return {
				"kty":"RSA",
				"alg":alg,
				"n":encodeArray(data[-1]),
				"e":encodeArray(data[-2]),
			};
		default: throw "Invalid argument";
	}
}
```

## AuthenticatorAssertionResponse

### clientDataJSON

See [clientDataJSON](#clientDataJSON)

### authenticatorData

See [authData](#authData)

### signature

```javascript
/**
 * https://w3c.github.io/webauthn/#signature-attestation-types
 */
function decodeSignature(publicKey, signature) {
	if(signature.constructor === Uint8Array) {
		signature = signature.buffer.slice(signature.byteOffset, signature.byteLength + signature.byteOffset);
	}
	if(signature.constructor !== ArrayBuffer) {
		return Promise.reject("Invalid argument: " + signature.constructor);
	}
	if(publicKey.kty == "EC") {
		/*
			0x30|b1|0x02|b2|r|0x02|b3|s
			b1 = Length of remaining data
			b2 = Length of r
			b3 = Length of s 
		 */
		var rs = new Uint8Array(64);
		var view = new DataView(signature);
		var offset = 0;
		if(view.getUint8(offset++) != 0x30) return Promise.reject("Invalid argument");
		var b1 = view.getUint8(offset++);
		if(view.getUint8(offset++) != 0x02) return Promise.reject("Invalid argument");
		var b2 = view.getUint8(offset++);
		if(b2 > 32) {
			b2--;
			offset++;
		}
		rs.set(new Uint8Array(view.buffer.slice(offset, offset+b2)), 0);
		offset += b2;
		if(view.getUint8(offset++) != 0x02) return Promise.reject("Invalid argument");
		var b3 = view.getUint8(offset++);
		if(b3 > 32) {
			b3--;
			offset++;
		}
		rs.set(new Uint8Array(view.buffer.slice(offset, offset+b3)), b2);
		return Promise.resolve(rs);
	} else {
		return Promise.resolve(signature);
	}
}
```
