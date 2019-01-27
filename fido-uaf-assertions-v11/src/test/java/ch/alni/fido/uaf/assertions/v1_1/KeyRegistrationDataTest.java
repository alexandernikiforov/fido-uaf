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

import ch.alni.fido.registry.v1_1.PublicKeyAlgAndEncoding;
import ch.alni.fido.registry.v1_1.SignatureAlgAndEncoding;
import ch.alni.fido.uaf.authnr.tlv.TlvStruct;

import static org.assertj.core.api.Assertions.assertThat;

public class KeyRegistrationDataTest {

    @Test
    public void testToTlvStruct() {
        final KeyRegistrationData krd = KeyRegistrationData.builder()
                .setAaid("ABCD#ABCD")
                .setAuthenticatorVersion(1)
                .setAuthenticationMode(0x01)
                .setSignatureAlgAndEncoding(SignatureAlgAndEncoding.ALG_SIGN_SECP256R1_ECDSA_SHA256_DER)
                .setPublicKeyAlgAndEncoding(PublicKeyAlgAndEncoding.ALG_KEY_ECC_X962_DER)
                .setFinalChallengeHash(new byte[]{0x01, 0x02})
                .setKeyId(new byte[]{0x03, 0x04})
                .setSignatureCounter(42)
                .setRegistrationCounter(21)
                .setUserAuthPubKey(new byte[]{0x05, 0x06})
                .build();

        final TlvStruct krdStruct = krd.toTlvStruct();

        assertThat(KeyRegistrationData.of(krdStruct)).isEqualTo(krd);
    }
}