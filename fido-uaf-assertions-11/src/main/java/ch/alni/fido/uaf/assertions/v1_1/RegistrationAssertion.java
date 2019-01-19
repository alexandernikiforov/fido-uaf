package ch.alni.fido.uaf.assertions.v1_1;

import com.google.auto.value.AutoValue;
import com.google.common.collect.ImmutableList;

import java.util.List;

import ch.alni.fido.uaf.authnr.tlv.TlvStruct;

@AutoValue
public abstract class RegistrationAssertion {
    public static Builder builder() {
        return new AutoValue_RegistrationAssertion.Builder()
                .setExtensionData(ImmutableList.of());
    }

    public abstract KeyRegistrationData keyRegistrationData();

    public abstract ImmutableList<TlvStruct> extensionData();

    @AutoValue.Builder
    public abstract static class Builder {
        public abstract Builder setKeyRegistrationData(KeyRegistrationData value);

        public abstract Builder setExtensionData(List<TlvStruct> value);

        public abstract RegistrationAssertion build();
    }
}
