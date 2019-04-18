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

```javascript
function replacer(k,v) {
	...
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
	...
}
```
