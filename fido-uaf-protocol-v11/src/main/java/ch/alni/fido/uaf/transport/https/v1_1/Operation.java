package ch.alni.fido.uaf.transport.https.v1_1;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public enum Operation {
    REG("Reg"), AUTH("Auth"), DEREG("Dereg");

    private final static Map<String, Operation> VALUE_MAP =
            Stream.of(values()).collect(Collectors.toMap(
                    Operation::getValue,
                    Function.identity()
            ));
    private final String value;

    Operation(String value) {
        this.value = value;
    }

    @JsonCreator
    public static Operation fromValue(String value) {
        return Optional.ofNullable(VALUE_MAP.get(value))
                .orElseThrow(() -> new IllegalArgumentException("invalid value " + value));
    }

    @JsonValue
    public String getValue() {
        return value;
    }

}
