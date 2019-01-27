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

package ch.alni.fido.uaf.protocol.v1_1;

import com.google.auto.value.AutoValue;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;

@AutoValue
@JsonDeserialize(builder = Extension.Builder.class)
public abstract class Extension {
    static Builder builder() {
        return new AutoValue_Extension.Builder();
    }

    @JsonGetter
    public abstract String id();

    @JsonGetter
    public abstract String data();

    @JsonGetter("fail_if_unknown")
    public abstract boolean failIfUnknown();

    @AutoValue.Builder
    @JsonPOJOBuilder(withPrefix = "set")
    abstract static class Builder {
        @JsonCreator
        static Builder create() {
            return Extension.builder();
        }

        @JsonSetter
        abstract Builder setId(String value);

        @JsonSetter
        abstract Builder setData(String value);

        @JsonSetter("fail_if_unknown")
        abstract Builder setFailIfUnknown(boolean value);

        abstract Extension build();
    }
}
