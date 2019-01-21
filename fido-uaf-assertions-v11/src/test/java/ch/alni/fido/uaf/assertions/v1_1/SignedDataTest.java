package ch.alni.fido.uaf.assertions.v1_1;

import org.junit.Test;

import ch.alni.fido.registry.v1_1.SignatureAlgAndEncoding;
import ch.alni.fido.uaf.authnr.tlv.TlvStruct;

import static org.assertj.core.api.Assertions.assertThat;

public class SignedDataTest {

    @Test
    public void testToTlvStruct() {
        final SignedData signedData = SignedData.builder()
                .setAaid("ABCD#ABCD")
                .setAuthenticatorVersion(1)
                .setAuthenticationMode(0x02)
                .setSignatureAlgAndEncoding(SignatureAlgAndEncoding.ALG_SIGN_SECP256R1_ECDSA_SHA256_DER)
                .setAuthenticatorNonce(new byte[]{0x11, 0x12, 0x11, 0x12, 0x11, 0x12, 0x11, 0x12, 0x11, 0x12})
                .setFinalChallengeHash(new byte[]{0x01, 0x02})
                .setTransactionContentHash(new byte[]{0x21, 0x22})
                .setKeyId(new byte[]{0x03, 0x04})
                .setSignatureCounter(42)
                .addExtension(Extension.builder()
                        .setCritical(true)
                        .setExtensionId(new byte[]{0x31})
                        .setExtensionData(new byte[]{0x61})
                        .build()
                )
                .build();

        final TlvStruct signedDataStruct = signedData.toTlvStruct();

        assertThat(SignedData.of(signedDataStruct)).isEqualTo(signedData);
    }
}