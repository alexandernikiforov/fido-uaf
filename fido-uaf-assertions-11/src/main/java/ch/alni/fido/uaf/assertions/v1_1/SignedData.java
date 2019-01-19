package ch.alni.fido.uaf.assertions.v1_1;

import com.google.auto.value.AutoValue;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;

import java.util.List;

import ch.alni.fido.uaf.authnr.tlv.TlvStruct;

@AutoValue
public abstract class SignedData {
    public static Builder builder() {
        return new AutoValue_SignedData.Builder()
                .setExtensionData(ImmutableList.of());
    }

    public abstract String aaid();

    public abstract AssertionInfo assertionInfo();

    @SuppressWarnings("mutable")
    public abstract byte[] authenticatorNonce();

    @SuppressWarnings("mutable")
    public abstract byte[] finalChallengeHash();

    @SuppressWarnings("mutable")
    public abstract byte[] transactionContentHash();

    @SuppressWarnings("mutable")
    public abstract byte[] keyId();

    public abstract Counters counters();

    public abstract ImmutableList<TlvStruct> extensionData();

    @AutoValue.Builder
    public abstract static class Builder {
        public abstract Builder setAaid(String value);

        public abstract Builder setAssertionInfo(AssertionInfo value);

        public abstract Builder setAuthenticatorNonce(byte[] value);

        public abstract Builder setFinalChallengeHash(byte[] value);

        public abstract Builder setTransactionContentHash(byte[] value);

        public abstract Builder setKeyId(byte[] keyId);

        public abstract Builder setCounters(Counters value);

        public abstract Builder setExtensionData(List<TlvStruct> value);

        abstract SignedData autoBuild();

        public SignedData build() {
            final SignedData signedData = autoBuild();
            final int authenticationMode = signedData.assertionInfo().authenticationMode();
            Preconditions.checkArgument(authenticationMode == 0x01 || authenticationMode == 0x02,
                    "Authentication mode must either 0x01 or 0x02, but is " + authenticationMode);
            if (authenticationMode == 0x01) {
                Preconditions.checkArgument(signedData.transactionContentHash().length == 0,
                        "The length of transaction content hash must 0, if this is authentication (mode 0x01)");
            }
            else {
                Preconditions.checkArgument(signedData.transactionContentHash().length > 0,
                        "The length of transaction content hash must 0, if this is transaction confirmation (mode 0x02)");
            }
            Preconditions.checkArgument(signedData.authenticatorNonce().length >= 8,
                    "The length of the authenticator nonce must be at least 8 bytes");
            return signedData;
        }
    }

}
