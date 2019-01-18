package ch.alni.fido.uaf.transport.https.v1_1;

import com.google.auto.value.AutoValue;
import com.google.common.collect.ImmutableList;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;

import java.util.List;
import java.util.Optional;

@AutoValue
@JsonDeserialize(builder = ServerResponse.Builder.class)
public abstract class ServerResponse {
    public static Builder builder() {
        return new AutoValue_ServerResponse.Builder()
                .setAdditionalTokens(ImmutableList.of());
    }

    @JsonGetter
    public abstract UafStatusCode statusCode();

    @JsonGetter
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public abstract ImmutableList<Token> additionalTokens();

    @JsonGetter
    @JsonInclude(JsonInclude.Include.NON_ABSENT)
    public abstract Optional<String> description();

    @JsonGetter
    @JsonInclude(JsonInclude.Include.NON_ABSENT)
    public abstract Optional<String> location();

    @JsonGetter
    @JsonInclude(JsonInclude.Include.NON_ABSENT)
    public abstract Optional<String> postData();

    @JsonGetter("newUAFRequest")
    @JsonInclude(JsonInclude.Include.NON_ABSENT)
    public abstract Optional<String> newUafRequest();

    @AutoValue.Builder
    @JsonPOJOBuilder(withPrefix = "set")
    public abstract static class Builder {
        @JsonCreator
        static Builder create() {
            return builder();
        }

        @JsonSetter
        public abstract Builder setStatusCode(UafStatusCode value);

        @JsonSetter
        public abstract Builder setAdditionalTokens(List<Token> value);

        @JsonSetter
        public abstract Builder setDescription(String value);

        @JsonSetter
        public abstract Builder setLocation(String value);

        @JsonSetter
        public abstract Builder setPostData(String value);

        @JsonSetter("newUAFRequest")
        public abstract Builder setNewUafRequest(String value);

        public abstract ServerResponse build();
    }

}
