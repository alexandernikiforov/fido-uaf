/*
 *      FIDO UAF 1.1 Protocol and Assertion Parser Support
 *      Copyright (C) 2019  Alexander Nikiforov
 *
 *      This program is free software: you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation, either version 3 of the License, or
 *      (at your option) any later version.
 *
 *      This program is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *      GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU General Public License
 *      along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

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
