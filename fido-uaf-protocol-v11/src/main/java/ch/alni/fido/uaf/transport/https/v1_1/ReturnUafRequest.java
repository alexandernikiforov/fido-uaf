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
@JsonDeserialize(builder = ReturnUafRequest.Builder.class)
public abstract class ReturnUafRequest {
    public static Builder builder() {
        return new AutoValue_ReturnUafRequest.Builder();
    }

    @JsonGetter
    public abstract UafStatusCode statusCode();

    @JsonGetter
    @JsonInclude(JsonInclude.Include.NON_ABSENT)
    public abstract Optional<String> uafRequest();

    @JsonGetter("op")
    @JsonInclude(JsonInclude.Include.NON_ABSENT)
    public abstract Optional<Operation> operation();

    @JsonGetter
    @JsonInclude(JsonInclude.Include.NON_ABSENT)
    public abstract Optional<Long> lifetimeMillis();

    @AutoValue.Builder
    @JsonPOJOBuilder(withPrefix = "set")
    public abstract static class Builder {
        @JsonCreator
        static Builder create() {
            return builder();
        }

        @JsonSetter
        public abstract Builder setStatusCode(UafStatusCode value);

        @JsonSetter("op")
        public abstract Builder setOperation(Operation value);

        @JsonSetter
        public abstract Builder setUafRequest(String value);

        @JsonSetter
        public abstract Builder setLifetimeMillis(long value);

        public abstract ReturnUafRequest build();
    }

}
