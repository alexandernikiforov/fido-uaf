package ch.alni.fido.registry.v1_1;

import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public enum PublicKeyAlgAndEncoding {

    ALG_KEY_ECC_X962_RAW(0x0100, "EC"),
    ALG_KEY_ECC_X962_DER(0x0101, "EC"),
    ALG_KEY_RSA_2048_RAW(0x0102, "RSA"),
    ALG_KEY_RSA_2048_DER(0x0103, "RSA");

    private final static Map<Integer, PublicKeyAlgAndEncoding> VALUE_MAP =
            Stream.of(values()).collect(Collectors.toMap(
                    PublicKeyAlgAndEncoding::getCode,
                    Function.identity()
            ));
    private final int code;
    private final String algorithm;

    PublicKeyAlgAndEncoding(int code, String algorithm) {
        this.code = code;
        this.algorithm = algorithm;
    }

    public static PublicKeyAlgAndEncoding fromCode(int code) {
        return Optional.ofNullable(VALUE_MAP.get(code))
                .orElseThrow(() -> new IllegalArgumentException("invalid code " + code));
    }

    public int getCode() {
        return code;
    }

    public String getAlgorithm() {
        return algorithm;
    }
}
