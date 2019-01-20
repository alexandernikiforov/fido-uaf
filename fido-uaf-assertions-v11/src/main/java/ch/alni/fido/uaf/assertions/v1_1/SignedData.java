package ch.alni.fido.uaf.assertions.v1_1;

import com.google.auto.value.AutoValue;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;

import java.nio.charset.StandardCharsets;
import java.util.List;

import ch.alni.fido.registry.v1_1.SignatureAlgAndEncoding;
import ch.alni.fido.uaf.authnr.tlv.TlvStruct;
import ch.alni.fido.uaf.authnr.tlv.UInt16;
import ch.alni.fido.uaf.authnr.tlv.UInt32;
import ch.alni.fido.uaf.authnr.tlv.UInt8;
import ch.alni.fido.uaf.authnr.tlv.UInts;
import ch.alni.fido.uaf.registry.v1_1.Tags;

@AutoValue
public abstract class SignedData {
    public static Builder builder() {
        return new AutoValue_SignedData.Builder().setExtensions(ImmutableList.of());
    }

    public abstract String aaid();

    public static SignedData of(TlvStruct signedDataStruct) {
        final int signedDataTag = signedDataStruct.tag().getValue();
        Preconditions.checkArgument(signedDataTag == Tags.TAG_UAFV1_SIGNED_DATA,
                "Unexpected signedDataTag value %d", signedDataTag);

        final SignedData.Builder builder = SignedData.builder();
        for (TlvStruct tlvStruct : signedDataStruct.tags()) {
            final int tag = tlvStruct.tag().getValue();
            switch (tag) {
                case Tags.TAG_AAID:
                    Preconditions.checkArgument(tlvStruct.data().isPresent(), "Data missing for tag TAG_AAID(%d)", tag);
                    tlvStruct.data().ifPresent(uInt8Array ->
                            builder.setAaid(new String(uInt8Array.toByteArray(), StandardCharsets.UTF_8))
                    );
                    break;
                case Tags.TAG_ASSERTION_INFO:
                    Preconditions.checkArgument(tlvStruct.data().isPresent(), "Data missing for tag TAG_ASSERTION_INFO(%d)", tag);
                    tlvStruct.data().ifPresent(uInt8Array -> {
                                final byte[] data = uInt8Array.toByteArray();
                                Preconditions.checkArgument(data.length == 5,
                                        "invalid length of data (%d) for tag TAG_ASSERTION_INFO(%d)", data.length, tag);
                                builder.setAuthenticatorVersion(UInt16.of(data[0], data[1]).getValue());
                                builder.setAuthenticationMode(UInt8.of(data[2]).getValue());
                                builder.setSignatureAlgAndEncoding(
                                        SignatureAlgAndEncoding.fromCode(UInt16.of(data[3], data[4]).getValue())
                                );
                            }
                    );
                    break;

                case Tags.TAG_AUTHENTICATOR_NONCE:
                    Preconditions.checkArgument(tlvStruct.data().isPresent(), "Data missing for tag TAG_AUTHENTICATOR_NONCE(%d)", tag);
                    tlvStruct.data().ifPresent(uInt8Array ->
                            builder.setAuthenticatorNonce(uInt8Array.toByteArray())
                    );
                    break;
                case Tags.TAG_FINAL_CHALLENGE_HASH:
                    Preconditions.checkArgument(tlvStruct.data().isPresent(), "Data missing for tag TAG_FINAL_CHALLENGE_HASH(%d)", tag);
                    tlvStruct.data().ifPresent(uInt8Array ->
                            builder.setFinalChallengeHash(uInt8Array.toByteArray())
                    );
                    break;
                case Tags.TAG_TRANSACTION_CONTENT_HASH:
                    Preconditions.checkArgument(tlvStruct.data().isPresent(), "Data missing for tag TAG_TRANSACTION_CONTENT_HASH(%d)", tag);
                    tlvStruct.data().ifPresent(uInt8Array ->
                            builder.setTransactionContentHash(uInt8Array.toByteArray())
                    );
                    break;
                case Tags.TAG_KEYID:
                    Preconditions.checkArgument(tlvStruct.data().isPresent(), "Data missing for tag TAG_KEYID(%d)", tag);
                    tlvStruct.data().ifPresent(uInt8Array ->
                            builder.setKeyId(uInt8Array.toByteArray())
                    );
                    break;
                case Tags.TAG_COUNTERS:
                    Preconditions.checkArgument(tlvStruct.data().isPresent(), "Data missing for tag TAG_COUNTERS(%d)", tag);
                    tlvStruct.data().ifPresent(uInt8Array -> {
                                final byte[] data = uInt8Array.toByteArray();
                                Preconditions.checkArgument(data.length == 4,
                                        "invalid length of data (%d) for tag TAG_COUNTERS(%d)", data.length, tag);
                                builder.setSignatureCounter(UInt32.of(data[0], data[1], data[2], data[3]).getValue());
                            }
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

    @SuppressWarnings("mutable")
    public abstract byte[] authenticatorNonce();

    @SuppressWarnings("mutable")
    public abstract byte[] finalChallengeHash();

    @SuppressWarnings("mutable")
    public abstract byte[] transactionContentHash();

    @SuppressWarnings("mutable")
    public abstract byte[] keyId();

    public abstract long signatureCounter();

    public abstract SignatureAlgAndEncoding signatureAlgAndEncoding();

    public abstract ImmutableList<Extension> extensions();

    /**
     * Converts to a TLV struct.
     *
     * @return TLC structure (not yet unsigned) corresponding to TAG_UAFV1_SIGNED_DATA
     */
    public TlvStruct toTlvStruct() {
        final TlvStruct result = TlvStruct.of(Tags.TAG_UAFV1_SIGNED_DATA,
                TlvStruct.of(Tags.TAG_AAID, aaid().getBytes(StandardCharsets.UTF_8)),
                TlvStruct.of(Tags.TAG_ASSERTION_INFO,
                        UInt16.of(authenticatorVersion()),
                        UInt8.of(authenticationMode()),
                        UInt16.of(signatureAlgAndEncoding().getCode())
                ),
                TlvStruct.of(Tags.TAG_AUTHENTICATOR_NONCE, authenticatorNonce()),
                TlvStruct.of(Tags.TAG_FINAL_CHALLENGE_HASH, finalChallengeHash()),
                TlvStruct.of(Tags.TAG_TRANSACTION_CONTENT_HASH, transactionContentHash()),
                TlvStruct.of(Tags.TAG_KEYID, keyId()),
                TlvStruct.of(Tags.TAG_COUNTERS, UInt32.of(signatureCounter()))
        );
        return TlvStruct.extend(result, Extension.toTlvStructList(extensions()));
    }

    @AutoValue.Builder
    public abstract static class Builder {
        public abstract Builder setAaid(String value);

        public abstract Builder setAuthenticatorVersion(int value);

        public abstract Builder setAuthenticationMode(int value);

        public abstract Builder setSignatureAlgAndEncoding(SignatureAlgAndEncoding value);

        public abstract Builder setAuthenticatorNonce(byte[] value);

        public abstract Builder setFinalChallengeHash(byte[] value);

        public abstract Builder setTransactionContentHash(byte[] value);

        public abstract Builder setKeyId(byte[] keyId);

        public abstract Builder setSignatureCounter(long value);

        public abstract Builder setExtensions(List<Extension> value);

        abstract ImmutableList.Builder<Extension> extensionsBuilder();

        public Builder addExtension(Extension extension) {
            extensionsBuilder().add(extension);
            return this;
        }

        abstract SignedData autoBuild();

        public SignedData build() {
            final SignedData signedData = autoBuild();
            final int authenticationMode = signedData.authenticationMode();

            Preconditions.checkState(UInts.isUInt8(signedData.authenticationMode()), "authenticationMode must be UINT8");
            Preconditions.checkState(UInts.isUInt16(signedData.authenticatorVersion()), "authenticatorVersion must be UINT16");

            Preconditions.checkArgument(authenticationMode == 0x01 || authenticationMode == 0x02,
                    "Authentication mode must either 0x01 or 0x02, but is " + authenticationMode);
            if (authenticationMode == 0x01) {
                Preconditions.checkArgument(signedData.transactionContentHash().length == 0,
                        "The length of transaction content hash must be 0, if this is authentication (mode 0x01)");
            }
            else {
                Preconditions.checkArgument(signedData.transactionContentHash().length > 0,
                        "The length of transaction content hash must greater than 0, if this is transaction confirmation (mode 0x02)");
            }
            Preconditions.checkArgument(signedData.authenticatorNonce().length >= 8,
                    "The length of the authenticator nonce must be at least 8 bytes");
            return signedData;
        }
    }
}
