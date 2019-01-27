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

package ch.alni.fido.uaf.protocol.v1_1;

import org.junit.Test;

import java.util.EnumSet;

import ch.alni.fido.registry.v1_1.UserVerificationMethod;

import static org.assertj.core.api.Assertions.assertThat;

public class EnumsTest {

    @Test
    public void toEnumSetLong() {
        assertThat(Enums.toEnumSet(UserVerificationMethod.class, UserVerificationMethod::getCode, 22))
                .containsOnly(
                        UserVerificationMethod.USER_VERIFY_PASSCODE,
                        UserVerificationMethod.USER_VERIFY_FINGERPRINT,
                        UserVerificationMethod.USER_VERIFY_FACEPRINT
                );
    }

    @Test
    public void toEnumSet1() {
    }

    @Test
    public void toBitValueLong() {
        assertThat(Enums.toBitValue(UserVerificationMethod::getCode, EnumSet.of(
                UserVerificationMethod.USER_VERIFY_PASSCODE,
                UserVerificationMethod.USER_VERIFY_FINGERPRINT,
                UserVerificationMethod.USER_VERIFY_FACEPRINT
        ))).isEqualTo(22);
    }

    @Test
    public void toBitValue1() {
    }
}