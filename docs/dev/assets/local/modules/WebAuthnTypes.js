export class PublicKeyCredentialEntity {
    name // string
    constructor(obj) {
        this.name = obj?.name;
    }
}

export class PublicKeyCredentialRpEntity extends PublicKeyCredentialEntity {
    id // string
    constructor(obj) {
        super(obj);
        this.id = obj?.id;
    }
    isEmpty() { return (this.name ?? this.id ?? undefined) === undefined }
    toJson() {
        return this.isEmpty()
            ? undefined
            : {
                name: this.name ?? undefined,
                id: this.id ?? undefined,
            };
    }
}

export class PublicKeyCredentialUserEntity extends PublicKeyCredentialEntity {
    get id() { return new TextEncoder("utf-8").encode(this.name); } // BufferSource
    displayName // string
    constructor(obj) {
        super(obj);
        this.displayName = obj?.displayName;
    }
    isEmpty() { return (this.name ?? this.displayName ?? undefined) === undefined }
    toJson() {
        return this.isEmpty()
            ? undefined
            : {
                name: this.name ?? undefined,
                id: this.id ?? undefined,
                displayName: this.displayName ?? undefined,
            };
    }
}

export class PublicKeyCredentialParameters {
    type // string
    alg // long
    constructor(obj) {
        this.type = obj?.type;
        this.alg = obj?.alg;
    }
    toJson() {
        return {
            type: this.type ?? undefined,
            alg: this.alg ?? undefined,
        }
    }
    static publicKey(alg) {
        return new PublicKeyCredentialParameters({
            type: "public-key",
            alg: alg,
        });
    }
}

export class PublicKeyCredentialDescriptor {
    type // string
    id // BufferSource
    transports // string[]
    constructor(obj) {
        this.type = obj?.type;
        this.id = obj?.id;
        this.transports = obj?.transports;
    }
    toJson() {
        return {
            type: this.type ?? undefined,
            id: this.id ?? undefined,
            transports: this.transports ?? undefined,
        }
    }
}

export class AuthenticatorSelectionCriteria {
    authenticatorAttachment // string
    residentKey // string
    // requireResidentKey // bool
    userVerification // string
    constructor(obj) {
        this.type = obj?.authenticatorAttachment;
        this.residentKey = obj?.residentKey;
        this.userVerification = obj?.userVerification;
    }
    isEmpty() { return (this.authenticatorAttachment ?? this.residentKey ?? this.userVerification ?? undefined) === undefined; }
    toJson() {
        return this.isEmpty()
            ? undefined
            : {
                authenticatorAttachment: this.authenticatorAttachment ?? undefined,
                residentKey: this.residentKey ?? undefined,
                userVerification: this.userVerification ?? undefined,
            };
    }
}

export class PublicKeyCredentialCreationOptions {
    rp = new PublicKeyCredentialRpEntity()
    user = new PublicKeyCredentialUserEntity()
    challenge // BufferSource
    pubKeyCredParams // PublicKeyCredentialParameters[]
    timeout // long
    excludeCredentials // PublicKeyCredentialDescriptor[]
    authenticatorSelection = new AuthenticatorSelectionCriteria() // AuthenticatorSelectionCriteria
    attestation // string
    extensions
    constructor(obj) {
        this.rp = new PublicKeyCredentialRpEntity(obj?.rp);
        this.user = new PublicKeyCredentialUserEntity(obj?.user);
        this.challenge = obj?.challenge;
        this.pubKeyCredParams = obj?.pubKeyCredParams?.map(t => new PublicKeyCredentialParameters(t));
        this.timeout = obj?.timeout;
        this.excludeCredentials = obj?.excludeCredentials?.map(t => new PublicKeyCredentialDescriptor(t));
        this.authenticatorSelection = new AuthenticatorSelectionCriteria(obj?.authenticatorSelection);
        this.attestation = obj?.attestation;
        this.extensions = obj?.extensions;
    }
    toJson() {
        return {
            rp: this.rp?.toJson(),
            user: this.user?.toJson(),
            challenge: this.challenge ?? undefined,
            pubKeyCredParams: this.pubKeyCredParams?.map(t => t?.toJson()),
            timeout: this.timeout ?? undefined,
            excludeCredentials: this.excludeCredentials?.map(t => t?.toJson()),
            authenticatorSelection: this.authenticatorSelection?.toJson(),
            attestation: this.attestation ?? undefined,
            extensions: this.extensions ?? undefined,
        }
    }
}

export class CredentialCreationOptions {
    publicKey = new PublicKeyCredentialCreationOptions()
    constructor(obj) {
        this.publicKey = new PublicKeyCredentialCreationOptions(obj?.publicKey);
    }
    toJson() {
        return {
            publicKey: this.publicKey?.toJson()
        }
    }
}

export class PublicKeyCredentialRequestOptions {
    challenge // BufferSource
    timeout // long
    rpId // string
    allowCredentials // PublicKeyCredentialDescriptor[]
    userVerification // string
    extensions
    constructor(obj) {
        this.challenge = obj?.challenge;
        this.timeout = obj?.timeout;
        this.rpId = obj?.rpId;
        this.allowCredentials = obj?.allowCredentials?.map(t => new PublicKeyCredentialDescriptor(t));
        this.userVerification = obj?.userVerification;
        this.extensions = obj?.extensions;
    }
    toJson() {
        return {
            challenge: this.challenge ?? undefined,
            timeout: this.timeout ?? undefined,
            rpId: this.rpId ?? undefined,
            allowCredentials: this.allowCredentials?.map(t => t?.toJson()),
            userVerification: this.userVerification ?? undefined,
            extensions: this.extensions ?? undefined,
        }
    }
}

export class CredentialRequestOptions {
    publicKey = new PublicKeyCredentialRequestOptions()
    constructor(obj) {
        this.publicKey = new PublicKeyCredentialRequestOptions(obj?.publicKey);
    }
    toJson() {
        return {
            publicKey: this.publicKey?.toJson()
        }
    }
}

export class Credential {
    id // string
    type // string    
    constructor(obj) {
        this.id = obj?.id;
        this.type = obj?.type;
    }
}

export class PublicKeyCredential extends Credential {
    rawId // ArrayBuffer
    response // AuthenticatorResponse (AuthenticatorAttestationResponse or AuthenticatorAssertionResponse)
    constructor(obj) {
        super(obj);
        this.rawId = obj?.rawId;
        if ("attestationObject" in (obj?.response ?? {})) this.response = new AuthenticatorAttestationResponse(obj?.response);
        if ("authenticatorData" in (obj?.response ?? {})) this.response = new AuthenticatorAssertionResponse(obj?.response);
    }
    toJson() {
        return {
            id: this.id ?? undefined,
            type: this.type ?? undefined,
            rawId: this.rawId ?? undefined,
            response: this.response?.toJson(),
        }
    }
}

export class AuthenticatorResponse {
    clientDataJSON // ArrayBuffer
    constructor(obj) {
        this.clientDataJSON = obj?.clientDataJSON;
    }
}

export class AuthenticatorAttestationResponse extends AuthenticatorResponse {
    attestationObject // ArrayBuffer
    constructor(obj) {
        super(obj);
        this.attestationObject = obj?.attestationObject;
    }
    toJson() {
        return {
            clientDataJSON: this.clientDataJSON ?? undefined,
            attestationObject: this.attestationObject ?? undefined
        }
    }
}

export class AuthenticatorAssertionResponse extends AuthenticatorResponse {
    authenticatorData // ArrayBuffer
    signature // ArrayBuffer
    userHandle // ArrayBuffer
    constructor(obj) {
        super(obj);
        this.authenticatorData = obj?.authenticatorData;
        this.signature = obj?.signature;
        this.userHandle = obj?.userHandle;
    }
    toJson() {
        return {
            clientDataJSON: this.clientDataJSON ?? undefined,
            authenticatorData: this.authenticatorData ?? undefined,
            signature: this.signature ?? undefined,
            userHandle: this.userHandle ?? undefined
        }
    }
}

export class AuthenticatorData {
    rpIdHash // ArrayBuffer
    flags // int
    get up() { return (this.flags & 0x01) != 0; }
    get uv() { return (this.flags & 0x04) != 0; }
    get at() { return (this.flags & 0x40) != 0; }
    get ed() { return (this.flags & 0x80) != 0; }
    signCount // int
    attestedCredentialData // AttestedCredentialData
    extensons // ArrayBuffer
    constructor(obj) {
        this.rpIdHash = obj?.rpIdHash;
        this.flags = obj?.flags;
        this.signCount = obj?.signCount;
        this.attestedCredentialData = new AttestedCredentialData(obj?.attestedCredentialData);
        this.extensons = obj?.extensions;
    }
    toJson() {
        return {
            rpIdHash: this.rpIdHash ?? undefined,
            flags: {
                value: this.flags ?? undefined,
                up: this.up,
                uv: this.uv,
                at: this.at,
                ed: this.ed,
            },
            signCount: this.signCount ?? undefined,
            attestedCredentialData: this.at ? this.attestedCredentialData?.toJson() : undefined,
            extensons: this.ed ? this.extensons ?? undefined : undefined,
        }
    }
}

export class AttestedCredentialData {
    aaguid // ArrayBuffer
    credentialId // ArrayBuffer
    credentialPublicKey // Jwk
    constructor(obj) {
        this.aaguid = obj?.aaguid;
        this.credentialId = obj?.credentialId;
        this.credentialPublicKey = obj?.credentialPublicKey;
    }
    toJson() {
        return {
            aaguid: this.aaguid,
            credentialId: this.credentialId,
            credentialPublicKey: this.credentialPublicKey,
        }
    }
}
