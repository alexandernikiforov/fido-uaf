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
