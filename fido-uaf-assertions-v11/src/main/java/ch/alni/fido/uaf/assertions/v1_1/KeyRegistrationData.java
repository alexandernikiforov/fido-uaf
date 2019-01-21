package ch.alni.fido.uaf.assertions.v1_1;

import com.google.auto.value.AutoValue;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;

import java.nio.charset.StandardCharsets;
import java.util.List;

import ch.alni.fido.registry.v1_1.PublicKeyAlgAndEncoding;
import ch.alni.fido.registry.v1_1.SignatureAlgAndEncoding;
import ch.alni.fido.uaf.authnr.tlv.TlvStruct;
import ch.alni.fido.uaf.authnr.tlv.UInt16;
import ch.alni.fido.uaf.authnr.tlv.UInt32;
import ch.alni.fido.uaf.authnr.tlv.UInt8;
import ch.alni.fido.uaf.authnr.tlv.UInt8Array;
import ch.alni.fido.uaf.authnr.tlv.UInts;
import ch.alni.fido.uaf.registry.v1_1.Tags;

@AutoValue
public abstract class KeyRegistrationData {
    public static Builder builder() {
        return new AutoValue_KeyRegistrationData.Builder().setExtensions(ImmutableList.of());
    }

    public abstract String aaid();

    public static KeyRegistrationData of(TlvStruct krd) {
        final int krdTag = krd.tag();
        Preconditions.checkArgument(krdTag == Tags.TAG_UAFV1_KRD,
                "Unexpected tag %s, expected TAG_UAFV1_KRD (%s)", krdTag, Tags.TAG_UAFV1_KRD);

        final Builder builder = builder();
        for (TlvStruct tlvStruct : krd.tags()) {
            final int tag = tlvStruct.tag();
            switch (tag) {
                case Tags.TAG_AAID:
                    Preconditions.checkArgument(tlvStruct.data().isPresent(), "Data missing for tag TAG_AAID(%d)", tag);
                    tlvStruct.data().ifPresent(tlvData ->
                            builder.setAaid(new String(tlvData.toByteArray(), StandardCharsets.UTF_8))
                    );
                    break;
                case Tags.TAG_ASSERTION_INFO:
                    Preconditions.checkArgument(tlvStruct.data().isPresent(), "Data missing for tag TAG_ASSERTION_INFO(%d)", tag);
                    tlvStruct.data().ifPresent(tlvData -> {
                        final byte[] data = tlvData.toByteArray();
                                Preconditions.checkArgument(data.length == 7,
                                        "Invalid length of data (%d) for tag TAG_ASSERTION_INFO(%d)", data.length, tag);
                                builder.setAuthenticatorVersion(UInt16.of(data[0], data[1]).getValue());
                                builder.setAuthenticationMode(UInt8.of(data[2]).getValue());
                                builder.setSignatureAlgAndEncoding(
                                        SignatureAlgAndEncoding.fromCode(UInt16.of(data[3], data[4]).getValue())
                                );
                                builder.setPublicKeyAlgAndEncoding(
                                        PublicKeyAlgAndEncoding.fromCode(UInt16.of(data[5], data[6]).getValue())
                                );
                            }
                    );
                    break;

                case Tags.TAG_FINAL_CHALLENGE_HASH:
                    Preconditions.checkArgument(tlvStruct.data().isPresent(), "Data missing for tag TAG_FINAL_CHALLENGE_HASH(%d)", tag);
                    tlvStruct.data().ifPresent(tlvData ->
                            builder.setFinalChallengeHash(tlvData.toByteArray())
                    );
                    break;
                case Tags.TAG_KEYID:
                    Preconditions.checkArgument(tlvStruct.data().isPresent(), "Data missing for tag TAG_KEYID(%d)", tag);
                    tlvStruct.data().ifPresent(tlvData ->
                            builder.setKeyId(tlvData.toByteArray())
                    );
                    break;
                case Tags.TAG_COUNTERS:
                    Preconditions.checkArgument(tlvStruct.data().isPresent(), "Data missing for tag TAG_COUNTERS(%d)", tag);
                    tlvStruct.data().ifPresent(tlvData -> {
                        final byte[] data = tlvData.toByteArray();
                                Preconditions.checkArgument(data.length == 8,
                                        "Invalid length of data (%d) for tag TAG_COUNTERS(%d)", data.length, tag);
                                builder.setSignatureCounter(UInt32.of(data[0], data[1], data[2], data[3]).getValue());
                                builder.setRegistrationCounter(UInt32.of(data[4], data[5], data[6], data[7]).getValue());
                            }
                    );
                    break;
                case Tags.TAG_PUB_KEY:
                    Preconditions.checkArgument(tlvStruct.data().isPresent(), "Data missing for tag TAG_PUB_KEY(%d)", tag);
                    tlvStruct.data().ifPresent(tlvData ->
                            builder.setUserAuthPubKey(tlvData.toByteArray())
                    );
                    break;
                case Tags.TAG_EXTENSION:
                case Tags.TAG_EXTENSION_CRITICAL:
                    builder.addExtension(Extension.of(tlvStruct));
                    break;
                default:
                    throw new IllegalArgumentException("Unexpected tag " + tag);
            }
        }

        return builder.build();
    }

    public abstract int authenticatorVersion();

    public abstract int authenticationMode();

    public abstract SignatureAlgAndEncoding signatureAlgAndEncoding();

    @SuppressWarnings("mutable")
    public abstract byte[] finalChallengeHash();

    @SuppressWarnings("mutable")
    public abstract byte[] keyId();

    public abstract PublicKeyAlgAndEncoding publicKeyAlgAndEncoding();

    public abstract long signatureCounter();

    @SuppressWarnings("mutable")
    public abstract byte[] userAuthPubKey();

    public abstract long registrationCounter();

    public abstract ImmutableList<Extension> extensions();

    /**
     * Converts to a TLV struct.
     *
     * @return TLC structure (not yet unsigned) corresponding to TAG_UAFV1_KRD
     */
    public TlvStruct toTlvStruct() {
        final TlvStruct result = TlvStruct.of(Tags.TAG_UAFV1_KRD,
                TlvStruct.of(Tags.TAG_AAID, UInt8Array.of(aaid().getBytes(StandardCharsets.UTF_8))),
                TlvStruct.of(Tags.TAG_ASSERTION_INFO,
                        UInt16.of(authenticatorVersion()),
                        UInt8.of(authenticationMode()),
                        UInt16.of(signatureAlgAndEncoding().getCode()),
                        UInt16.of(publicKeyAlgAndEncoding().getCode())
                ),
                TlvStruct.of(Tags.TAG_FINAL_CHALLENGE_HASH, UInt8Array.of(finalChallengeHash())),
                TlvStruct.of(Tags.TAG_KEYID, UInt8Array.of(keyId())),
                TlvStruct.of(Tags.TAG_COUNTERS,
                        UInt32.of(signatureCounter()),
                        UInt32.of(registrationCounter())
                ),
                TlvStruct.of(Tags.TAG_PUB_KEY, UInt8Array.of(userAuthPubKey()))
        );

        return TlvStruct.extend(result, Extension.toTlvStructList(extensions()));
    }

    @AutoValue.Builder
    public abstract static class Builder {
        public abstract Builder setAaid(String value);

        public abstract Builder setAuthenticatorVersion(int value);

        public abstract Builder setAuthenticationMode(int value);

        public abstract Builder setSignatureAlgAndEncoding(SignatureAlgAndEncoding value);

        public abstract Builder setPublicKeyAlgAndEncoding(PublicKeyAlgAndEncoding value);

        public abstract Builder setFinalChallengeHash(byte[] value);

        public abstract Builder setKeyId(byte[] keyId);

        public abstract Builder setSignatureCounter(long value);

        public abstract Builder setRegistrationCounter(long value);

        public abstract Builder setUserAuthPubKey(byte[] value);

        public abstract Builder setExtensions(List<Extension> value);

        abstract ImmutableList.Builder<Extension> extensionsBuilder();

        public Builder addExtension(Extension extension) {
            extensionsBuilder().add(extension);
            return this;
        }

        abstract KeyRegistrationData autoBuild();

        public KeyRegistrationData build() {
            KeyRegistrationData krd = autoBuild();

            Preconditions.checkState(UInts.isUInt8(krd.authenticationMode()), "authenticationMode must be UINT8");
            Preconditions.checkState(UInts.isUInt16(krd.authenticatorVersion()), "authenticatorVersion must be UINT16");

            Preconditions.checkArgument(krd.authenticationMode() == 0x01,
                    "authentication mode must be set to 0x01");

            return krd;
        }
    }


}
