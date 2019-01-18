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
@JsonDeserialize(builder = GetUafRequest.Builder.class)
public abstract class GetUafRequest {
    public static Builder builder() {
        return new AutoValue_GetUafRequest.Builder();
    }

    @JsonGetter("op")
    @JsonInclude(JsonInclude.Include.NON_ABSENT)
    public abstract Optional<Operation> operation();

    @JsonGetter
    @JsonInclude(JsonInclude.Include.NON_ABSENT)
    public abstract Optional<String> previousRequest();

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

        @JsonSetter("op")
        public abstract Builder setOperation(Operation value);

        @JsonSetter
        public abstract Builder setPreviousRequest(String value);

        @JsonSetter
        public abstract Builder setContext(String value);

        public abstract GetUafRequest build();
    }

}
