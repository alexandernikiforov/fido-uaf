package ch.alni.fido.uaf.protocol.v1_1;

import com.google.auto.value.AutoValue;
import com.google.common.collect.ImmutableList;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;

import java.util.List;

@AutoValue
@JsonDeserialize(builder = AuthenticationRequest.Builder.class)
public abstract class AuthenticationRequest {
    public static Builder builder() {
        return new AutoValue_AuthenticationRequest.Builder()
                .setTransactions(ImmutableList.of());
    }

    @JsonGetter
    public abstract OperationHeader header();

    @JsonGetter
    public abstract String challenge();

    @JsonGetter("transaction")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public abstract ImmutableList<Transaction> transactions();

    @JsonGetter
    public abstract Policy policy();

    @AutoValue.Builder
    @JsonPOJOBuilder(withPrefix = "set")
    public abstract static class Builder {
        @JsonCreator
        static Builder create() {
            return AuthenticationRequest.builder();
        }

        @JsonSetter
        public abstract Builder setHeader(OperationHeader value);

        @JsonSetter
        public abstract Builder setChallenge(String value);

        @JsonSetter("transaction")
        public abstract Builder setTransactions(List<Transaction> value);

        @JsonSetter
        public abstract Builder setPolicy(Policy value);

        public abstract AuthenticationRequest build();
    }
}