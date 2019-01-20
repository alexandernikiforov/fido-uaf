package ch.alni.fido.uaf.assertions.v1_1;

import com.google.auto.value.AutoValue;
import com.google.common.collect.ImmutableList;

import java.util.List;

@AutoValue
public abstract class RegistrationAssertion {
    public static Builder builder() {
        return new AutoValue_RegistrationAssertion.Builder()
                .setExtensions(ImmutableList.of());
    }

    public abstract KeyRegistrationData keyRegistrationData();

    public abstract ImmutableList<Extension> extensions();

    @AutoValue.Builder
    public abstract static class Builder {
        public abstract Builder setKeyRegistrationData(KeyRegistrationData value);

        public abstract Builder setExtensions(List<Extension> value);

        abstract ImmutableList.Builder<Extension> extensionsBuilder();

        public Builder addExtension(Extension extension) {
            extensionsBuilder().add(extension);
            return this;
        }

        public abstract RegistrationAssertion build();
    }
}
