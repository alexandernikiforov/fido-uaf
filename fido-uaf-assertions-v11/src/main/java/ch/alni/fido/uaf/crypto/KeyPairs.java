package ch.alni.fido.uaf.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;

import ch.alni.fido.registry.v1_1.SignatureAlgAndEncoding;

public final class KeyPairs {
    private final static SecureRandom SECURE_RANDOM = new SecureRandom();

    private KeyPairs() {
    }

    public static KeyPair generate(SignatureAlgAndEncoding signatureAlgAndEncoding) {
        switch (signatureAlgAndEncoding) {
            case ALG_SIGN_SECP256R1_ECDSA_SHA256_DER:
                return doCreate("ECDSA", new ECGenParameterSpec("secp256r1"));
            case ALG_SIGN_SECP256K1_ECDSA_SHA256_DER:
                return doCreate("ECDSA", new ECGenParameterSpec("secp256k1"));
            default:
                throw new IllegalStateException("unsupported signature algorithm: " + signatureAlgAndEncoding);
        }
    }

    private static KeyPair doCreate(String algorithm, AlgorithmParameterSpec parameterSpec) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
            generator.initialize(parameterSpec, SECURE_RANDOM);
            return generator.generateKeyPair();
        }
        catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            throw new IllegalStateException(e);
        }
    }
}
