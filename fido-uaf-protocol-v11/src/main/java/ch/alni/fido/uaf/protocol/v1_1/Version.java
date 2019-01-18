package ch.alni.fido.uaf.protocol.v1_1;

import com.google.auto.value.AutoValue;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;

@AutoValue
@JsonDeserialize(builder = Version.Builder.class)
public abstract class Version {
    public static Builder builder() {
        return new AutoValue_Version.Builder();
    }

    @JsonGetter
    public abstract int minor();

    @JsonGetter
    public abstract int major();

    @AutoValue.Builder
    @JsonPOJOBuilder(withPrefix = "set")
    public abstract static class Builder {

        @JsonCreator
        static Builder create() {
            return Version.builder();
        }

        @JsonSetter
        public abstract Builder setMinor(int value);

        @JsonSetter
        public abstract Builder setMajor(int value);

        public abstract Version build();
    }
}
