/*
 *      FIDO UAF 1.1 Protocol and Assertion Parser Support
 *      Copyright (C) 2019  Alexander Nikiforov
 *
 *      This program is free software: you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation, either version 3 of the License, or
 *      (at your option) any later version.
 *
 *      This program is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *      GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU General Public License
 *      along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

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
