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

package ch.alni.fido.uaf.helpers;

import java.security.PrivateKey;

import ch.alni.fido.uaf.assertions.v1_1.AuthenticationAssertion;
import ch.alni.fido.uaf.assertions.v1_1.Extension;
import ch.alni.fido.uaf.assertions.v1_1.RegistrationAssertion;
import ch.alni.fido.uaf.authnr.tlv.TlvStruct;
import ch.alni.fido.uaf.authnr.tlv.UInt8Array;
import ch.alni.fido.uaf.crypto.AuthenticatorSigner;
import ch.alni.fido.uaf.registry.v1_1.Tags;

/**
 * Helper to create assertions.
 */
public final class Assertions {
    private Assertions() {
    }

    public static String encodeWithBasicSurrogateAttestation(PrivateKey privateKey, RegistrationAssertion registrationAssertion) {
        // sign the key reg data
        final TlvStruct krdStruct = registrationAssertion.keyRegistrationData().toTlvStruct();

        // use encoding
        final byte[] signature = AuthenticatorSigner.sign(
                privateKey,
                registrationAssertion.keyRegistrationData().signatureAlgAndEncoding(),
                krdStruct.toByteArray()
        );

        // create the final struct
        final TlvStruct assertionStruct = TlvStruct.of(Tags.TAG_UAFV1_REG_ASSERTION,
                krdStruct,
                TlvStruct.of(Tags.TAG_ATTESTATION_BASIC_SURROGATE,
                        TlvStruct.of(Tags.TAG_SIGNATURE, UInt8Array.of(signature))
                )
        );

        // add possible extensions (unsigned)
        TlvStruct.extend(assertionStruct, Extension.toTlvStructList(registrationAssertion.extensions()));

        return assertionStruct.toBase64UrlEncoded();
    }

    public static String encode(PrivateKey privateKey, AuthenticationAssertion authenticationAssertion) {
        // sign the key reg data
        final TlvStruct signedDataStruct = authenticationAssertion.signedData().toTlvStruct();

        // use encoding
        final byte[] signature = AuthenticatorSigner.sign(
                privateKey,
                authenticationAssertion.signedData().signatureAlgAndEncoding(),
                signedDataStruct.toByteArray()
        );

        // create the final struct
        final TlvStruct assertionStruct = TlvStruct.of(Tags.TAG_UAFV1_AUTH_ASSERTION,
                signedDataStruct,
                TlvStruct.of(Tags.TAG_SIGNATURE, UInt8Array.of(signature))
        );

        // add possible extensions (unsigned)
        TlvStruct.extend(assertionStruct, Extension.toTlvStructList(authenticationAssertion.extensions()));

        return assertionStruct.toBase64UrlEncoded();
    }
}
