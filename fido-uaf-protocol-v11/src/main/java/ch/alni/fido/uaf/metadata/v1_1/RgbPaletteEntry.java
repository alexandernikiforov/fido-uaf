package ch.alni.fido.uaf.metadata.v1_1;

import com.google.auto.value.AutoValue;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;

@AutoValue
@JsonDeserialize(builder = RgbPaletteEntry.Builder.class)
public abstract class RgbPaletteEntry {
    public static Builder builder() {
        return new AutoValue_RgbPaletteEntry.Builder();
    }

    @JsonGetter
    abstract public int r();

    @JsonGetter
    abstract public int g();

    @JsonGetter
    abstract public int b();

    @AutoValue.Builder
    @JsonPOJOBuilder(withPrefix = "set")
    public abstract static class Builder {

        @JsonCreator
        static Builder create() {
            return builder();
        }

        @JsonSetter
        abstract public Builder r(int value);

        @JsonSetter
        abstract public Builder g(int value);

        @JsonSetter
        abstract public Builder b(int value);

        public abstract RgbPaletteEntry build();

    }
}