package ch.alni.fido.uaf.protocol.v1_1;

import com.google.auto.value.AutoValue;
import com.google.common.collect.ImmutableList;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;

import java.util.List;

@AutoValue
@JsonDeserialize(builder = AuthenticationResponse.Builder.class)
abstract public class AuthenticationResponse {
    public static Builder builder() {
        return new AutoValue_AuthenticationResponse.Builder();
    }

    @JsonGetter
    abstract public OperationHeader header();

    @JsonGetter
    abstract public String fcParams();

    @JsonGetter
    abstract public ImmutableList<AuthenticatorSignAssertion> assertions();

    @AutoValue.Builder
    @JsonPOJOBuilder(withPrefix = "set")
    public abstract static class Builder {
        @JsonCreator
        static Builder create() {
            return builder();
        }

        @JsonSetter
        public abstract Builder setHeader(OperationHeader value);

        @JsonSetter
        public abstract Builder setFcParams(String value);

        @JsonSetter
        public abstract Builder setAssertions(List<AuthenticatorSignAssertion> value);

        public abstract AuthenticationResponse build();

    }
}