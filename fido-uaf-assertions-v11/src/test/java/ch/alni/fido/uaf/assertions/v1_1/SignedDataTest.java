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