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