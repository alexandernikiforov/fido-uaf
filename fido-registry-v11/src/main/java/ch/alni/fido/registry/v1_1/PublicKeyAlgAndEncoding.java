package ch.alni.fido.registry.v1_1;

import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public enum PublicKeyAlgAndEncoding {

    ALG_KEY_ECC_X962_RAW(0x0100),
    ALG_KEY_ECC_X962_DER(0x0101),
    ALG_KEY_RSA_2048_RAW(0x0102),
    ALG_KEY_RSA_2048_DER(0x0103);

    private final static Map<Integer, PublicKeyAlgAndEncoding> VALUE_MAP =
            Stream.of(values()).collect(Collectors.toMap(
                    PublicKeyAlgAndEncoding::getCode,
                    Function.identity()
            ));
    private final int code;

    PublicKeyAlgAndEncoding(int code) {
        this.code = code;
    }

    public static PublicKeyAlgAndEncoding fromCode(int code) {
        return Optional.ofNullable(VALUE_MAP.get(code))
                .orElseThrow(() -> new IllegalArgumentException("invalid code " + code));
    }

    public int getCode() {
        return code;
    }
}
