export class PublicKeyCredentialEntity {
    name // string
}

export class PublicKeyCredentialRpEntity extends PublicKeyCredentialEntity {
    id // string
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
    constructor(type, alg) {
        this.type = type;
        this.alg = alg;
    }
    toJson() {
        return {
            type: this.type ?? undefined,
            alg: this.alg ?? undefined,
        }
    }
}

export class PublicKeyCredentialDescriptor {
    type // string
    id // BufferSource
    transports // string[]
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
    toJson() {
        return {
            publicKey: this.publicKey?.toJson()
        }
    }
}

export class Credential {
    id // string
    type // string    
}

export class PublicKeyCredential extends Credential {
    rawId // ArrayBuffer
    response // AuthenticatorResponse (AuthenticatorAttestationResponse or AuthenticatorAssertionResponse)
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
}

export class AuthenticatorAttestationResponse extends AuthenticatorResponse {
    attestationObject // ArrayBuffer
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
    get up() { return (this.flags & 0x01) != 0 ;}
    get uv() { return (this.flags & 0x04) != 0 ;}
    get at() { return (this.flags & 0x40) != 0 ;}
    get ed() { return (this.flags & 0x80) != 0 ;}
    signCount // int
    attestedCredentialData // AttestedCredentialData
    extensons // ArrayBuffer
}

export class AttestedCredentialData {
    aaguid // ArrayBuffer
    credentialId // ArrayBuffer
    credentialPublicKey // Jwk
}
