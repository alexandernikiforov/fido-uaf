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
@JsonDeserialize(builder = RegistrationResponse.Builder.class)
abstract public class RegistrationResponse {
    public static Builder builder() {
        return new AutoValue_RegistrationResponse.Builder();
    }

    @JsonGetter
    abstract public OperationHeader header();

    @JsonGetter
    abstract public String fcParams();

    @JsonGetter
    abstract public ImmutableList<AuthenticatorRegistrationAssertion> assertions();

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
        public abstract Builder setAssertions(List<AuthenticatorRegistrationAssertion> value);

        public abstract RegistrationResponse build();

    }
}