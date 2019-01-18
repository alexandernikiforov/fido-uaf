package ch.alni.fido.uaf.metadata.v1_1;

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
@JsonDeserialize(builder = DisplayPNGCharacteristicsDescriptor.Builder.class)
public abstract class DisplayPNGCharacteristicsDescriptor {
    public static Builder builder() {
        return new AutoValue_DisplayPNGCharacteristicsDescriptor.Builder()
                .setPlte(ImmutableList.of());
    }

    @JsonGetter
    abstract public long width();

    @JsonGetter
    abstract public long height();

    @JsonGetter
    abstract public int bitDepth();

    @JsonGetter
    abstract public int colorType();

    @JsonGetter
    abstract public int compression();

    @JsonGetter
    abstract public int filter();

    @JsonGetter
    abstract public int interlace();

    @JsonGetter
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    abstract public ImmutableList<RgbPaletteEntry> plte();

    @AutoValue.Builder
    @JsonPOJOBuilder(withPrefix = "set")
    public abstract static class Builder {

        @JsonCreator
        static Builder create() {
            return builder();
        }

        @JsonSetter
        public abstract Builder setWidth(long value);

        @JsonSetter
        public abstract Builder setHeight(long value);

        @JsonSetter
        public abstract Builder setBitDepth(int value);

        @JsonSetter
        public abstract Builder setColorType(int value);

        @JsonSetter
        public abstract Builder setCompression(int value);

        @JsonSetter
        public abstract Builder setFilter(int value);

        @JsonSetter
        public abstract Builder setInterlace(int value);

        @JsonSetter
        public abstract Builder setPlte(List<RgbPaletteEntry> value);

        public abstract DisplayPNGCharacteristicsDescriptor build();
    }


}
