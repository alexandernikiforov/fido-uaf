package ch.alni.fido.uaf.crypto;


import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;

import ch.alni.fido.registry.v1_1.SignatureAlgAndEncoding;

public final class AuthenticatorSigner {
    private final static SecureRandom SECURE_RANDOM = new SecureRandom();

    private AuthenticatorSigner() {
    }

    public static byte[] sign(PrivateKey privateKey, SignatureAlgAndEncoding signatureAlgAndEncoding, byte[] data) {
        switch (signatureAlgAndEncoding) {
            case ALG_SIGN_SECP256R1_ECDSA_SHA256_DER:
            case ALG_SIGN_SECP256K1_ECDSA_SHA256_DER:
            case ALG_SIGN_RSASSA_PSS_SHA256_DER:
            case ALG_SIGN_RSA_EMSA_PKCS1_SHA256_DER:
                return doSign(privateKey, signatureAlgAndEncoding, data);
            default:
                throw new IllegalStateException("unsupported signature algorithm: " + signatureAlgAndEncoding);
        }
    }

    private static byte[] doSign(PrivateKey privateKey, SignatureAlgAndEncoding signatureAlgAndEncoding, byte[] data) {
        try {
            Signature signature = Signature.getInstance(signatureAlgAndEncoding.getAlgorithm(), BouncyCastleProvider.PROVIDER_NAME);
            signature.initSign(privateKey, SECURE_RANDOM);
            signature.update(data);
            return signature.sign();
        }
        catch (NoSuchAlgorithmException | NoSuchProviderException | SignatureException e) {
            throw new IllegalStateException(e);
        }
        catch (InvalidKeyException e) {
            throw new IllegalArgumentException("the signer key does not correspond to the selected algorithm", e);
        }
    }
}
