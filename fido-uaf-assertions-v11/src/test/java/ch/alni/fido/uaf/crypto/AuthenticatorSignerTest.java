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
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Security;

import ch.alni.fido.registry.v1_1.SignatureAlgAndEncoding;

import static org.junit.Assert.assertNotNull;

public class AuthenticatorSignerTest {

    @BeforeClass
    public static void setUpClass() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @AfterClass
    public static void tearDownClass() {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    }

    @Test
    public void testSign() {
        final KeyPair keyPair = KeyPairs.generate(SignatureAlgAndEncoding.ALG_SIGN_SECP256R1_ECDSA_SHA256_DER);

        final byte[] signature = AuthenticatorSigner.sign(
                keyPair.getPrivate(),
                SignatureAlgAndEncoding.ALG_SIGN_SECP256R1_ECDSA_SHA256_DER,
                "Hello World".getBytes(StandardCharsets.UTF_8)
        );

        assertNotNull(signature);
    }
}