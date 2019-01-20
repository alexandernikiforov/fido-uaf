package ch.alni.fido.uaf.assertions.v1_1;

import com.google.auto.value.AutoValue;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;

import java.security.PublicKey;
import java.util.List;

import ch.alni.fido.uaf.authnr.tlv.TlvStruct;

@AutoValue
public abstract class KeyRegistrationData {
    public static Builder builder() {
        return new AutoValue_KeyRegistrationData.Builder()
                .setExtensionData(ImmutableList.of());
    }

    public abstract String aaid();

    public abstract AssertionInfo assertionInfo();

    @SuppressWarnings("mutable")
    public abstract byte[] finalChallengeHash();

    @SuppressWarnings("mutable")
    public abstract byte[] keyId();

    public abstract Counters counters();

    public abstract PublicKey userAuthPubKey();

    public abstract ImmutableList<TlvStruct> extensionData();

    @AutoValue.Builder
    public abstract static class Builder {
        public abstract Builder setAaid(String value);

        public abstract Builder setAssertionInfo(AssertionInfo value);

        public abstract Builder setFinalChallengeHash(byte[] value);

        public abstract Builder setKeyId(byte[] keyId);

        public abstract Builder setCounters(Counters value);

        public abstract Builder setUserAuthPubKey(PublicKey value);

        public abstract Builder setExtensionData(List<TlvStruct> value);

        abstract KeyRegistrationData autoBuild();

        public KeyRegistrationData build() {
            KeyRegistrationData keyRegistrationData = autoBuild();

            Preconditions.checkArgument(keyRegistrationData.assertionInfo().authenticationMode() == 0x01,
                    "authentication mode must be set to 0x01");

            return keyRegistrationData;
        }
    }

}
