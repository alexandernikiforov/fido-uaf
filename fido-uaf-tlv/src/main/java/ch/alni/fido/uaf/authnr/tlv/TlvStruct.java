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

import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

@AutoValue
public abstract class TlvStruct {

    private static final int TAG_HEADER_LENGTH = 4;

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

    public static TlvStruct of(int tag, TlvStruct first, TlvStruct... rest) {
        Preconditions.checkNotNull(first, "at least one tag must be not null");

        final int length = computeLength(first, rest);

        final ImmutableList<TlvStruct> tags = null == rest ?
                new ImmutableList.Builder<TlvStruct>().add(first).build() :
                new ImmutableList.Builder<TlvStruct>().add(first).add(rest).build();

        return builder()
                .setTag(UInt16.of(tag))
                .setLength(UInt16.of(length))
                .setComposite(true)
                .setTags(tags)
                .build();
    }

    /**
     * Builds a non-recursive tag.
     *
     * @param tag   the tag ID
     * @param first first part of the tag values
     * @param rest  the rest of the tag values (can be empty)
     * @return a non-recursive TLV structure containing the tag values in the data section in the order in which they
     * are provided as parameters to this method
     */
    public static TlvStruct of(int tag, TagValue first, TagValue... rest) {
        Preconditions.checkNotNull(first, "at least one tag value must be provided");

        // compute the length
        final int length = null == rest ? first.length() :
                Stream.of(rest)
                        .mapToInt(TagValue::length)
                        .reduce(first.length(), (result, value) -> result + value);

        // build an array from the data
        final byte[] data = new byte[length];

        // copy first
        System.arraycopy(first.toByteArray(), 0, data, 0, first.length());

        // copy rest
        if (null != rest) {
            int pos = first.length(); // start after the first tag
            for (TagValue tagValue : rest) {
                System.arraycopy(tagValue.toByteArray(), 0, data, pos, tagValue.length());
                // move the pointer
                pos += tagValue.length();
            }
        }

        return builder()
                .setTag(UInt16.of(tag))
                .setLength(UInt16.of(length))
                .setComposite(false)
                .setData(UInt8Array.of(data))
                .build();
    }


    public abstract UInt16 tag();

    public abstract UInt16 length();

    public abstract int lengthAsInt();

    public abstract boolean composite();

    public abstract Optional<UInt8Array> data();

    public abstract ImmutableList<TlvStruct> tags();

    /**
     * Returns a new TLV structure that is result of appending the parameter tags to the tags of the TLV structure
     * provided as the first parameter. This method can be called on for composite tags.
     */
    public static TlvStruct extend(TlvStruct tlvStruct, List<TlvStruct> tlvStructs) {
        Preconditions.checkNotNull(tlvStruct, "TLV structure to be extended must not be null");
        Preconditions.checkState(tlvStruct.composite(), "cannot append TLV tags to a non-composite tag");

        if (tlvStructs.isEmpty()) {
            return tlvStruct;
        }

        // compute the length
        final int length = tlvStruct.lengthAsInt() + tlvStructs.stream()
                .mapToInt(TlvStruct::lengthAsInt)
                .reduce(0, (result, value) -> TAG_HEADER_LENGTH + result + value);

        final ImmutableList<TlvStruct> tags = new ImmutableList.Builder<TlvStruct>()
                .addAll(tlvStruct.tags())
                .addAll(tlvStructs)
                .build();

        return tlvStruct.toBuilder()
                .setLength(UInt16.of(length))
                .setTags(tags)
                .build();
    }

    private static int computeLength(TlvStruct first, TlvStruct[] rest) {
        return null == rest ? TAG_HEADER_LENGTH + first.lengthAsInt() :
                Stream.of(rest)
                        .mapToInt(TlvStruct::lengthAsInt)
                        .reduce(
                                TAG_HEADER_LENGTH + first.lengthAsInt(),
                                (result, value) -> TAG_HEADER_LENGTH + result + value
                        );
    }

    public abstract Builder toBuilder();

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
