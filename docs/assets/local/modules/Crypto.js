import { encodeArray } from "./base64.js";

/**
 * Convert Cose key to JWK
 * @see https://datatracker.ietf.org/doc/html/rfc8152
 * @see https://www.iana.org/assignments/cose/cose.xhtml
 * @param {object} data - Cose
 * @returns {object} - JWK
 */
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

/**
 * Returns WebCrypto algorithm
 * @param {object} jwk - JWK
 * @param {string} alg - JWA identifier
 * @returns {object} - WebCrypto algorithm
 */
export function getAlgorithm(jwk, alg) {
	var algorithm;
	switch (jwk.kty) {
		case "EC":
			algorithm = {
				"name": "ECDSA",
				"namedCurve": jwk.crv,
			};
			break;
		case "RSA":
			algorithm = {
				"name": "RSASSA-PKCS1-v1_5",
			};
			break;
		default:
			throw new Error("invalid argument: kty=" + jwk.kty);
	}
	var a = alg ?? jwk.alg ?? "S256";
	switch (a) {
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
			throw new Error("invalid argument: alg=" + a);
	}
	return algorithm;
}

/**
 * Converts JWK to WebCrypto compatible format then invokes crypto.subtle.importKey
 * @see https://w3c.github.io/webcrypto/#SubtleCrypto-method-importKey
 * @param {object} jwk - JWK
 * @param {string} alg - JWA identifier
 * @returns {Promise<CryptoKey} - WebCrypto key
 */
export async function importJWK(jwk, alg) {
	var key;
	switch (jwk.kty) {
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
			throw new Error("invalid argument: kty=" + jwk.kty);
	}
	var algorithm = getAlgorithm(jwk, alg);
	//console.log("importKey key: "+ encodeJson(key));
	//console.log("importKey algorithm: "+ encodeJson(algorithm));
	return await crypto.subtle.importKey("jwk", key, algorithm, false, ["verify"]);
}

/**
 * Invokes crypto.subtle.digest to calculate SHA-256 digest
 * @see https://w3c.github.io/webcrypto/#SubtleCrypto-method-digest
 * @param {ArrayBuffer} data 
 * @returns {Promise<ArrayBuffer}
 */
export async function sha256(data) {
	return await crypto.subtle.digest("SHA-256", data);
}

/**
 * Invokes crypto.getRandomValues to generate random byte array
 * @see https://w3c.github.io/webcrypto/#dfn-Crypto-method-getRandomValues
 * @param {int} length - number of bytes
 * @returns {Uint8Array}
 */
export function getRandomBytes(length) {
	var array = new Uint8Array(length ?? 32);
	crypto.getRandomValues(array);
	return array;
}
