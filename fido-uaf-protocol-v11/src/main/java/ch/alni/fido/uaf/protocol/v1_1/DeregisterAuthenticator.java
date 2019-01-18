package ch.alni.fido.uaf.protocol.v1_1;

import com.google.auto.value.AutoValue;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;

@AutoValue
@JsonDeserialize(builder = DeregisterAuthenticator.Builder.class)
public abstract class DeregisterAuthenticator {
    public static Builder builder() {
        return new AutoValue_DeregisterAuthenticator.Builder();
    }

    @JsonGetter("aaid")
    public abstract String aaid();

    @JsonGetter("keyID")
    public abstract String keyId();

    @AutoValue.Builder
    @JsonPOJOBuilder(withPrefix = "set")
    public abstract static class Builder {
        @JsonCreator
        static Builder create() {
            return DeregisterAuthenticator.builder();
        }

        @JsonSetter
        public abstract Builder setAaid(String value);

        @JsonSetter("keyID")
        public abstract Builder setKeyId(String value);

        public abstract DeregisterAuthenticator build();
    }
}