/*
 *      FIDO UAF 1.1 Assertions Generator and Parser
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

package ch.alni.fido.uaf.authnr.tlv;

import com.google.auto.value.AutoValue;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

@AutoValue
public abstract class TlvStruct {
    static Builder builder() {
        return new AutoValue_TlvStruct.Builder()
                .setTags(ImmutableList.of());
    }

    public static TlvStruct of(int tag, byte[] data) {
        return builder()
                .setTag(UInt16.of(tag))
                .setLength(UInt16.of(null == data ? 0 : data.length))
                .setComposite(false)
                .setData(UInt8Array.of(data))
                .build();
    }

    public static TlvStruct of(int tag, TlvStruct... tags) {
        final int length = Stream.of(tags)
                .map(TlvStruct::lengthAsInt)
                .reduce(0, (result, value) -> 4 + result + value);

        return builder()
                .setTag(UInt16.of(tag))
                .setLength(UInt16.of(length))
                .setComposite(true)
                .setTags(Arrays.asList(tags))
                .build();
    }

    public abstract UInt16 tag();

    public abstract UInt16 length();

    public abstract int lengthAsInt();

    public abstract boolean composite();

    public abstract Optional<UInt8Array> data();

    public abstract ImmutableList<TlvStruct> tags();

    @AutoValue.Builder
    abstract static class Builder {
        abstract Builder setTag(UInt16 value);

        abstract Builder setLength(UInt16 value);

        abstract Builder setLengthAsInt(int length);

        abstract Builder setComposite(boolean value);

        abstract UInt16 length();

        abstract Builder setData(UInt8Array data);

        abstract Builder setTags(List<TlvStruct> tags);

        abstract TlvStruct autoBuild();

        TlvStruct build() {
            if (null != length()) {
                setLengthAsInt(length().getValue());
            }

            final TlvStruct tlvStruct = autoBuild();

            Preconditions.checkArgument(tlvStruct.tag().getValue() <= 0x3FFF, "" +
                    "only the first 14 bits should be used in tags to accommodate the limitations of some hardware platforms");

            final boolean dataPresent = tlvStruct.data().isPresent();
            final boolean tagsEmpty = tlvStruct.tags().isEmpty();

            Preconditions.checkArgument((dataPresent && tagsEmpty) || !dataPresent && !tagsEmpty,
                    "either tags or data must be present");

            if (tlvStruct.composite()) {
                Preconditions.checkArgument(!tagsEmpty, "a composite tag must contain tags");
                Preconditions.checkArgument((tlvStruct.tag().getValue() & 0x1000) > 0,
                        "a composite tag must be recursive");
            }

            return tlvStruct;
        }
    }
}
