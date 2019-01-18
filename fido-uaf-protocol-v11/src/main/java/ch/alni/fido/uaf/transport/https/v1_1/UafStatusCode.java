package ch.alni.fido.uaf.transport.https.v1_1;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public enum UafStatusCode {
    OK(1200),
    ACCEPTED(1202),
    BAD_REQUEST(1400),
    UNAUTHORIZED(1401),
    FORBIDDEN(1403),
    NOT_FOUND(1404),
    REQUEST_TIMEOUT(1408),
    UNKNOWN_AAID(1480),
    UNKNOWN_KEY_ID(1481),
    CHANNEL_BINDING_REFUSED(1490),
    REQUEST_INVALID(1491),
    UNACCEPTABLE_AUTHENTICATOR(1492),
    REVOKED_AUTHENTICATOR(1493),
    UNACCEPTABLE_KEY(1494),
    UNACCEPTABLE_ALGORITHM(1495),
    UNACCEPTABLE_ATTESTATION(1496),
    UNACCEPTABLE_CLIENT_CAPABILITIES(1497),
    UNACCEPTABLE_CONTENT(1498),
    INTERNAL_SERVER_ERROR(1500);

    private final static Map<Integer, UafStatusCode> VALUE_MAP =
            Stream.of(values()).collect(Collectors.toMap(
                    UafStatusCode::getCode,
                    Function.identity()
            ));
    private final int code;

    UafStatusCode(int code) {
        this.code = code;
    }

    @JsonCreator
    public static UafStatusCode fromValue(int value) {
        return Optional.ofNullable(VALUE_MAP.get(value))
                .orElseThrow(() -> new IllegalArgumentException("invalid code " + value));
    }

    @JsonValue
    public int getCode() {
        return code;
    }
}

