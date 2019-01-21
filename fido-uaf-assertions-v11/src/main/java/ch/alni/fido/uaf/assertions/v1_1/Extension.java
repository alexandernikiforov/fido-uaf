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
                "Invalid extension tag %d", extTag);

        Preconditions.checkArgument(extTlvStruct.tags().size() == 2, "Invalid size of the extension tag");

        final Extension.Builder builder = Extension.builder();
        for (TlvStruct tlvStruct : extTlvStruct.tags()) {
            final int tag = tlvStruct.tag();

            switch (tag) {
                case Tags.TAG_EXTENSION_ID:
                    Preconditions.checkArgument(tlvStruct.data().isPresent(), "Data missing for tag TAG_EXTENSION_ID(%d)", tag);
                    tlvStruct.data().ifPresent(uInt8Array ->
                            builder.setExtensionId(uInt8Array.toByteArray())
                    );
                    break;
                case Tags.TAG_EXTENSION_DATA:
                    Preconditions.checkArgument(tlvStruct.data().isPresent(), "Data missing for tag TAG_EXTENSION_DATA(%d)", tag);
                    tlvStruct.data().ifPresent(uInt8Array ->
                            builder.setExtensionData(uInt8Array.toByteArray())
                    );
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
