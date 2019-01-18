package ch.alni.fido.uaf.transport.https.v1_1;

import com.google.auto.value.AutoValue;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;

import java.util.Optional;

@AutoValue
@JsonDeserialize(builder = SendUafResponse.Builder.class)
public abstract class SendUafResponse {
    public static Builder builder() {
        return new AutoValue_SendUafResponse.Builder();
    }

    @JsonGetter
    public abstract String uafResponse();

    @JsonGetter
    @JsonInclude(JsonInclude.Include.NON_ABSENT)
    public abstract Optional<String> context();

    @AutoValue.Builder
    @JsonPOJOBuilder(withPrefix = "set")
    public abstract static class Builder {
        @JsonCreator
        static Builder create() {
            return builder();
        }

        @JsonSetter
        public abstract Builder setUafResponse(String value);

        @JsonSetter
        public abstract Builder setContext(String value);

        public abstract SendUafResponse build();
    }

}
