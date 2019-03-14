# Web Authentication API Tester

https://psteniusubi.github.io/webauthn-tester/

## Requirements

You need a FIDO authenticator to use the tool. If you are using Windows 10 with 1809 update or later, then you only need to [set up Windows Hello](https://support.microsoft.com/en-us/help/4028017/windows-learn-about-windows-hello-and-set-it-up) as your FIDO authenticator and use Microsoft Edge to run the tool.

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
