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

package ch.alni.fido.uaf.assertions.v1_1;

import com.google.auto.value.AutoValue;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;

import java.util.List;
import java.util.stream.Collectors;

import ch.alni.fido.uaf.authnr.tlv.TlvStruct;
import ch.alni.fido.uaf.authnr.tlv.UInt8Array;
import ch.alni.fido.uaf.registry.v1_1.Tags;

@AutoValue
public abstract class Extension {
    public static Builder builder() {
        return new AutoValue_Extension.Builder();
    }

    public static ImmutableList<TlvStruct> toTlvStructList(List<Extension> extensionList) {
        return new ImmutableList.Builder<TlvStruct>()
                .addAll(extensionList.stream()
                        .map(extension -> TlvStruct.of(extension.critical() ? Tags.TAG_EXTENSION_CRITICAL : Tags.TAG_EXTENSION,
                                TlvStruct.of(Tags.TAG_EXTENSION_ID, UInt8Array.of(extension.extensionId())),
                                TlvStruct.of(Tags.TAG_EXTENSION_DATA, UInt8Array.of(extension.extensionData()))
                        ))
                        .collect(Collectors.toList()))
                .build();
    }

    public static Extension of(TlvStruct extTlvStruct) {
        final int extTag = extTlvStruct.tag();
        Preconditions.checkArgument(extTag == Tags.TAG_EXTENSION || extTag == Tags.TAG_EXTENSION_CRITICAL,
                "Invalid extension tag %s", extTag);

        Preconditions.checkArgument(extTlvStruct.tags().size() == 2, "Invalid size of the extension tag");

        final Extension.Builder builder = Extension.builder();
        for (TlvStruct tlvStruct : extTlvStruct.tags()) {
            final int tag = tlvStruct.tag();

            switch (tag) {
                case Tags.TAG_EXTENSION_ID:
                    Preconditions.checkArgument(tlvStruct.data().isPresent(), "Data missing for tag TAG_EXTENSION_ID(%s)", tag);
                    tlvStruct.data().ifPresent(uInt8Array ->
                            builder.setExtensionId(uInt8Array.toByteArray())
                    );
                    break;
                case Tags.TAG_EXTENSION_DATA:
                    Preconditions.checkArgument(tlvStruct.data().isPresent(), "Data missing for tag TAG_EXTENSION_DATA(%s)", tag);
                    tlvStruct.data().ifPresent(uInt8Array ->
                            builder.setExtensionData(uInt8Array.toByteArray())
                    );
                    break;
                default:
                    throw new IllegalArgumentException("Unexpected tag " + tag);
            }
        }
        builder.setCritical(extTag == Tags.TAG_EXTENSION_CRITICAL);
        return builder.build();
    }

    @SuppressWarnings("mutable")
    public abstract byte[] extensionId();

    @SuppressWarnings("mutable")
    public abstract byte[] extensionData();

    public abstract boolean critical();

    @AutoValue.Builder
    public abstract static class Builder {
        public abstract Builder setExtensionId(byte[] value);

        public abstract Builder setExtensionData(byte[] value);

        public abstract Builder setCritical(boolean value);

        public abstract Extension build();

    }
}
