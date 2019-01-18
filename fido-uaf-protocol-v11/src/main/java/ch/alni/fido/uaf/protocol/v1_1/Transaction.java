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

import ch.alni.fido.uaf.metadata.v1_1.DisplayPNGCharacteristicsDescriptor;

@AutoValue
@JsonDeserialize(builder = Transaction.Builder.class)
public abstract class Transaction {
    public static Builder builder() {
        return new AutoValue_Transaction.Builder()
                .setTcDisplayPNGCharacteristics(ImmutableList.of());
    }

    @JsonGetter
    public abstract String contentType();

    @JsonGetter
    public abstract String content();

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public abstract ImmutableList<DisplayPNGCharacteristicsDescriptor> tcDisplayPNGCharacteristics();

    @AutoValue.Builder
    @JsonPOJOBuilder(withPrefix = "set")
    public abstract static class Builder {
        @JsonCreator
        static Builder create() {
            return Transaction.builder();
        }

        @JsonSetter
        public abstract Builder setContentType(String value);

        @JsonSetter
        public abstract Builder setContent(String value);

        @JsonSetter
        public abstract Builder setTcDisplayPNGCharacteristics(List<DisplayPNGCharacteristicsDescriptor> value);

        public abstract Transaction build();
    }
}
