/**
 * depends on
 * base64url.js
 * cbor.js (from https://github.com/paroga/cbor-js)
 */

function toBoolean(value) { 
	if("true" == value) return true;
	if("false" == value) return false;
	return null;
}

function encodeArray(array) {
	return btoaUrlSafe(Array.from(new Uint8Array(array), t => String.fromCharCode(t)).join(""));
}

function decodeArray(value) {
	return Uint8Array.from(atobUrlSafe(value), t => t.charCodeAt(0));
}

/**
 * replacer method for JSON.stringify
 */
function replacer(k,v) {
	if(v && v.constructor === Uint8Array) {
		return encodeArray(v);
	}
	if(v && v.constructor === ArrayBuffer) {
		return encodeArray(v);
	}
	if(v && v.constructor === PublicKeyCredential) {
		return {
			// https://w3c.github.io/webappsec-credential-management/#credential
			id: v.id,
			type: v.type,
			// https://w3c.github.io/webauthn/#publickeycredential
			rawId: v.rawId,
			response: v.response,
		};
	}
	if(v && v.constructor === AuthenticatorAttestationResponse) {
		return {
			// https://w3c.github.io/webauthn/#authenticatorresponse
			clientDataJSON: v.clientDataJSON,
			// https://w3c.github.io/webauthn/#authenticatorattestationresponse
			attestationObject: v.attestationObject, 
		};
	}
	if(v && v.constructor === AuthenticatorAssertionResponse) {
		return {
			// https://w3c.github.io/webauthn/#authenticatorresponse
			clientDataJSON: v.clientDataJSON,
			// https://w3c.github.io/webauthn/#authenticatorassertionresponse
			authenticatorData: v.authenticatorData, 
			signature: v.signature, 
			userHandle: v.userHandle, 
		};
	}
	if(v && v.constructor === CryptoKey) {
		return {
			// https://w3c.github.io/webcrypto/#cryptokey-interface
			type: v.type,
			extractable: v.extractable,
			algorithm: v.algorithm,
			usages: v.usages,
		};
	}
	return v;
}

/**
 * invokes JSON.stringify with default parameters
 */
function encodeJson(value) {
	return JSON.stringify(value, replacer, 2);
}

function PublicKeyCredential_isUserVerifyingPlatformAuthenticatorAvailable() {
	return new Promise((resolve, reject) => PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
		.then(value => resolve(value))
		.catch(error => reject(error)));
}

function navigator_credentials_create(options) {
	return new Promise((resolve, reject) => navigator.credentials.create(options)
		.then(value => resolve(value))
		.catch(error => reject(error)));
}

function navigator_credentials_get(options) {
	return new Promise((resolve, reject) => navigator.credentials.get(options)
		.then(value => resolve(value))
		.catch(error => reject(error)));
}

/**
 * https://w3c.github.io/webauthn/#dom-publickeycredentialcreationoptions-challenge
 * https://w3c.github.io/webauthn/#dom-publickeycredentialrequestoptions-challenge
 */
function getRandomChallenge() {
	var array = new Uint8Array(32);
	crypto.getRandomValues(array);
	return Promise.resolve(array);
}

/**
 * https://w3c.github.io/webauthn/#dom-authenticatorresponse-clientdatajson
 */
function decodeClientDataJSON(data) {
	return JSON.parse(Array.from(new Uint8Array(data), t => String.fromCharCode(t)).join(""))
}

/**
 * https://w3c.github.io/webauthn/#dom-authenticatorattestationresponse-attestationobject
 */
function decodeAttestationObject(data) {
	return CBOR.decode(data);
}

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

/**
 * https://www.w3.org/TR/WebCryptoAPI/#algorithm-overview
 * https://www.w3.org/TR/WebCryptoAPI/#jwk-mapping
 */
function getAlgorithm(jwk, alg) {
	var algorithm;
	switch(jwk.kty) {
		case "EC":
			algorithm = {
				"name":"ECDSA",
				"namedCurve": jwk.crv,
			};
			break;
		case "RSA":
			algorithm = {
				"name": "RSASSA-PKCS1-v1_5",
			};
			break;
		default:
			return Promise.reject("Invalid argument: kty=" + jwk.kty);
	}
	var a = alg || jwk.alg || "S256";
	switch(a) {
		case "RS512":
		case "ES512":
		case "S512":
			algorithm.hash = {
				name: "SHA-512"
			};
			break;
		case "RS384":
		case "ES384":
		case "S384":
			algorithm.hash = {
				name: "SHA-384"
			};
			break;
		case "RS256":
		case "ES256":
		case "S256":
			algorithm.hash = {
				name: "SHA-256"
			};
			break;
		default:
			return Promise.reject("Invalid argument: alg=" + a);
	}
	return algorithm;
}

function importJWK(jwk, alg) {
	var key;
	switch(jwk.kty) {
		case "EC":
			key = {
				"kty": jwk.kty,
				"crv": jwk.crv,
				"x": jwk.x,
				"y": jwk.y
			};
			break;
		case "RSA":
			key = {
				"kty": jwk.kty,
				"n": jwk.n,
				"e": jwk.e
			};
			break;
		default:
			return Promise.reject("Invalid argument: kty=" + jwk.kty);
	}
	var algorithm = getAlgorithm(jwk, alg);
	//console.log("importKey key: "+ encodeJson(key));
	//console.log("importKey algorithm: "+ encodeJson(algorithm));
	return crypto.subtle.importKey("jwk", key, algorithm, false, ["verify"]);
}

/**
 * https://w3c.github.io/webauthn/#credentialpublickey
 */
function decodeCredentialPublicKey(data) {
	var obj = CBOR.decode(data);
	return coseToJwk(obj);
}

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

function sha256(data) {
	return crypto.subtle.digest("SHA-256", data);
}

/**
 * https://w3c.github.io/webauthn/#assertion-signature
 * https://w3c.github.io/webauthn/#op-get-assertion
 */
function verifyAssertionSignature(publicKeyCredential, publicKey) {	
	
	var alg = publicKey.alg || "S256";

	var key_promise = importJWK(publicKey, alg);
	
	key_promise
		.then(value => console.log("importKey: return " + encodeJson(value)))
		.catch(e => console.error("importKey: " + JSON.stringify(e)));
	
	var hash_promise = sha256(publicKeyCredential.response.clientDataJSON);
	
	hash_promise
		.then(value => console.log("sha256: return " + replacer(null, value)))
		.catch(e => console.error("sha256: " + e));
	
	var signed_promise = hash_promise.then(value => {
		var signed = new Uint8Array(publicKeyCredential.response.authenticatorData.byteLength + value.byteLength);
		signed.set(new Uint8Array(publicKeyCredential.response.authenticatorData), 0);
		signed.set(new Uint8Array(value), publicKeyCredential.response.authenticatorData.byteLength);
		return signed;
	});
	
	signed_promise
		.then(value => console.log("signed: return " + replacer(null, value)))
		.catch(e => console.error("signed: " + e));
		
	var signature_promise = decodeSignature(publicKey, publicKeyCredential.response.signature);

	signature_promise
		.then(value => console.log("signature: return " + replacer(null, value)))
		.catch(e => console.error("signature: " + e));
	
	var verify_promise = Promise.all([key_promise,signed_promise,signature_promise])
		.then(all => crypto.subtle.verify(getAlgorithm(publicKey, alg), all[0], all[2], all[1]));

	verify_promise
		.then(value => console.log("verify: return " + value))
		.catch(e => console.error("verify: " + e));

	return verify_promise;
}
