package ch.alni.fido.uaf.protocol.v1_1;

import org.junit.Test;

import java.util.EnumSet;

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