package ch.alni.fido.uaf.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import ch.alni.fido.registry.v1_1.PublicKeyAlgAndEncoding;

public final class PublicKeys {
    private PublicKeys() {
    }

    public static PublicKey toPublicKey(PublicKeyAlgAndEncoding publicKeyAlgAndEncoding, byte[] data) {
        switch (publicKeyAlgAndEncoding) {
            case ALG_KEY_ECC_X962_DER:
            case ALG_KEY_RSA_2048_DER:
                return restorePublicKey(publicKeyAlgAndEncoding, data);

            default:
                throw new IllegalStateException("unsupported public key encoding: " + publicKeyAlgAndEncoding);
        }
    }

    private static PublicKey restorePublicKey(PublicKeyAlgAndEncoding publicKeyAlgAndEncoding, byte[] data) {
        try {
            final KeyFactory keyFactory = KeyFactory.getInstance(publicKeyAlgAndEncoding.getAlgorithm(), BouncyCastleProvider.PROVIDER_NAME);
            final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(data);
            return keyFactory.generatePublic(keySpec);
        }
        catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException(e);
        }
        catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new IllegalStateException(e);
        }
    }
}
