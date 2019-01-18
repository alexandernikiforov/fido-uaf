package ch.alni.fido.uaf.protocol.v1_1;

import com.google.auto.value.AutoValue;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;

@AutoValue
@JsonDeserialize(builder = RegistrationRequest.Builder.class)
public abstract class RegistrationRequest {
    public static Builder builder() {
        return new AutoValue_RegistrationRequest.Builder();
    }

    @JsonGetter
    public abstract OperationHeader header();

    @JsonGetter
    public abstract String challenge();

    @JsonGetter
    public abstract String username();

    @JsonGetter
    public abstract Policy policy();

    @AutoValue.Builder
    @JsonPOJOBuilder(withPrefix = "set")
    public abstract static class Builder {
        @JsonCreator
        static Builder create() {
            return RegistrationRequest.builder();
        }

        @JsonSetter
        public abstract Builder setHeader(OperationHeader value);

        @JsonSetter
        public abstract Builder setChallenge(String value);

        @JsonSetter
        public abstract Builder setUsername(String value);

        @JsonSetter
        public abstract Builder setPolicy(Policy value);

        public abstract RegistrationRequest build();
    }
}