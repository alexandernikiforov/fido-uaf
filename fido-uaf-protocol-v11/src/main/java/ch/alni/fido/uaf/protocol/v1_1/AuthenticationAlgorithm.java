package ch.alni.fido.uaf.protocol.v1_1;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public enum AuthenticationAlgorithm {

    ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW(0x0001),
    ALG_SIGN_SECP256R1_ECDSA_SHA256_DER(0x0002),
    ALG_SIGN_RSASSA_PSS_SHA256_RAW(0x0003),
    ALG_SIGN_RSASSA_PSS_SHA256_DER(0x0004),
    ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW(0x0005),
    ALG_SIGN_SECP256K1_ECDSA_SHA256_DER(0x0006),
    ALG_SIGN_SM2_SM3_RAW(0x0007),
    ALG_SIGN_RSA_EMSA_PKCS1_SHA256_RAW(0x0008),
    ALG_SIGN_RSA_EMSA_PKCS1_SHA256_DER(0x0009);

    private final static Map<Integer, AuthenticationAlgorithm> VALUE_MAP =
            Stream.of(values()).collect(Collectors.toMap(
                    AuthenticationAlgorithm::getCode,
                    Function.identity()
            ));
    private final int code;

    AuthenticationAlgorithm(int code) {
        this.code = code;
    }

    @JsonCreator
    public static AuthenticationAlgorithm fromCode(int code) {
        return Optional.ofNullable(VALUE_MAP.get(code))
                .orElseThrow(() -> new IllegalArgumentException("invalid value " + code));
    }

    @JsonValue
    public int getCode() {
        return code;
    }
}
