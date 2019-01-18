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
@JsonDeserialize(builder = DeregistrationRequest.Builder.class)
public abstract class DeregistrationRequest {
    public static Builder builder() {
        return new AutoValue_DeregistrationRequest.Builder();
    }

    @JsonGetter
    public abstract OperationHeader header();

    @JsonGetter
    public abstract ImmutableList<DeregisterAuthenticator> authenticators();

    @AutoValue.Builder
    @JsonPOJOBuilder(withPrefix = "set")
    public abstract static class Builder {

        @JsonCreator
        static Builder create() {
            return DeregistrationRequest.builder();
        }

        @JsonSetter
        public abstract Builder setHeader(OperationHeader value);

        @JsonSetter
        public abstract Builder setAuthenticators(List<DeregisterAuthenticator> value);

        public abstract DeregistrationRequest build();
    }
}