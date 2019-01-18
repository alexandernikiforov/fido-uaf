package ch.alni.fido.uaf.transport.https.v1_1;

import com.google.auto.value.AutoValue;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;

@AutoValue
@JsonDeserialize(builder = Token.Builder.class)
public abstract class Token {
    public static Builder builder() {
        return new AutoValue_Token.Builder();
    }

    @JsonGetter
    public abstract TokenType type();

    @JsonGetter
    public abstract String value();

    @AutoValue.Builder
    @JsonPOJOBuilder(withPrefix = "set")
    public abstract static class Builder {
        @JsonCreator
        static Builder create() {
            return builder();
        }

        @JsonSetter
        public abstract Builder setType(TokenType value);

        @JsonSetter
        public abstract Builder setValue(String value);

        public abstract Token build();
    }

}
