package ch.alni.fido.uaf.assertions.v1_1;

import com.google.auto.value.AutoValue;
import com.google.common.collect.ImmutableList;

import java.util.List;

import ch.alni.fido.uaf.authnr.tlv.TlvStruct;

@AutoValue
public abstract class AuthenticationAssertion {
    public static Builder builder() {
        return new AutoValue_AuthenticationAssertion.Builder()
                .setExtensionData(ImmutableList.of());
    }

    public abstract SignedData signedData();

    public abstract ImmutableList<TlvStruct> extensionData();

    @AutoValue.Builder
    public abstract static class Builder {
        public abstract Builder setSignedData(SignedData value);

        public abstract Builder setExtensionData(List<TlvStruct> value);

        public abstract AuthenticationAssertion build();
    }
}
