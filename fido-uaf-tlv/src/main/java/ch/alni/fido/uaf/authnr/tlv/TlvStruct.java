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

import java.util.Base64;
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

    /**
     * Creates a TLV structure from the supplied data.
     *
     * @throws TlvParserException if the given data cannot be parsed properly
     */
    public static TlvStruct of(byte[] data) {
        Preconditions.checkArgument(null != data && data.length > 0, "data cannot be null or empty");
        return new RecursiveDescentParser().parse(data);
    }

    /**
     * Builds a recursive tag.
     */
    public static TlvStruct of(int tag, TlvStruct first, TlvStruct... rest) {
        Preconditions.checkNotNull(first, "at least one tag must be not null");

        final int length = computeLength(first, rest);

        final ImmutableList<TlvStruct> tags = null == rest ?
                new ImmutableList.Builder<TlvStruct>().add(first).build() :
                new ImmutableList.Builder<TlvStruct>().add(first).add(rest).build();

        return builder()
                .setTag(tag)
                .setLength(length)
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

        // copy the first TLV structure
        System.arraycopy(first.toByteArray(), 0, data, 0, first.length());

        // copy the rest of structures
        if (null != rest) {
            int pos = first.length(); // start after the first tag
            for (TagValue tagValue : rest) {
                System.arraycopy(tagValue.toByteArray(), 0, data, pos, tagValue.length());
                // move the pointer
                pos += tagValue.length();
            }
        }

        return builder()
                .setTag(tag)
                .setLength(length)
                .setComposite(false)
                .setData(ImmutableByteArray.of(data))
                .build();
    }

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
        final int length = tlvStruct.length() + tlvStructs.stream()
                .mapToInt(TlvStruct::length)
                .reduce(0, (result, value) -> TAG_HEADER_LENGTH + result + value);

        final ImmutableList<TlvStruct> tags = new ImmutableList.Builder<TlvStruct>()
                .addAll(tlvStruct.tags())
                .addAll(tlvStructs)
                .build();

        return tlvStruct.toBuilder()
                .setLength(length)
                .setTags(tags)
                .build();
    }

    private static int computeLength(TlvStruct first, TlvStruct[] rest) {
        return null == rest ? TAG_HEADER_LENGTH + first.length() :
                Stream.of(rest)
                        .mapToInt(TlvStruct::length)
                        .reduce(
                                TAG_HEADER_LENGTH + first.length(),
                                (result, value) -> TAG_HEADER_LENGTH + result + value
                        );
    }

    public abstract boolean composite();

    public abstract int tag();

    public abstract ImmutableList<TlvStruct> tags();

    public abstract int length();

    public abstract Optional<ImmutableByteArray> data();

    /**
     * Serializes itself to a byte array.
     */
    public final byte[] toByteArray() {
        return new RecursiveDescentSerializer().toByteArray(this);
    }

    /**
     * Serializes itself to a Base64Url encoded string.
     */
    public final String toBase64UrlEncoded() {
        final byte[] byteArray = new RecursiveDescentSerializer().toByteArray(this);
        return Base64.getUrlEncoder().encodeToString(byteArray);
    }

    abstract Builder toBuilder();

    @AutoValue.Builder
    abstract static class Builder {
        abstract Builder setTag(int value);

        abstract Builder setLength(int value);

        abstract Builder setComposite(boolean value);

        abstract Builder setData(ImmutableByteArray data);

        abstract Builder setTags(List<TlvStruct> tags);

        abstract TlvStruct autoBuild();

        TlvStruct build() {
            final TlvStruct tlvStruct = autoBuild();

            Preconditions.checkArgument(tlvStruct.tag() <= 0x3FFF, "" +
                    "only the first 14 bits should be used in tags to accommodate the limitations of some hardware platforms");

            Preconditions.checkArgument(UInts.isUInt16(tlvStruct.tag()), "tag must be compatible with UINT16");
            Preconditions.checkArgument(UInts.isUInt16(tlvStruct.length()), "tag must be compatible with UINT16");

            final boolean dataPresent = tlvStruct.data().isPresent();
            final boolean tagsEmpty = tlvStruct.tags().isEmpty();

            Preconditions.checkArgument((dataPresent && tagsEmpty) || !dataPresent && !tagsEmpty,
                    "either tags or data must be present");

            if (tlvStruct.composite()) {
                Preconditions.checkArgument(!tagsEmpty, "a composite tag must contain tags");
                Preconditions.checkArgument((tlvStruct.tag() & 0x1000) > 0,
                        "a composite tag must be recursive");
            }

            return tlvStruct;
        }
    }
}
