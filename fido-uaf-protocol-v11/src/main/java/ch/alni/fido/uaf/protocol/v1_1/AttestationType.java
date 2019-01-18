package ch.alni.fido.uaf.protocol.v1_1;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public enum AttestationType {

    TAG_ATTESTATION_BASIC_FULL(0x3E07),
    TAG_ATTESTATION_BASIC_SURROGATE(0x3E08),
    TAG_ATTESTATION_ECDAA(0x3E09);

    private final static Map<Integer, AttestationType> VALUE_MAP =
            Stream.of(values()).collect(Collectors.toMap(
                    AttestationType::getCode,
                    Function.identity()
            ));
    private final int code;

    AttestationType(int code) {
        this.code = code;
    }

    @JsonCreator
    public static AttestationType fromCode(int code) {
        return Optional.ofNullable(VALUE_MAP.get(code))
                .orElseThrow(() -> new IllegalArgumentException("invalid value " + code));
    }

    @JsonValue
    public int getCode() {
        return code;
    }
}
