package ch.alni.fido.uaf.protocol.v1_1;

import com.google.auto.value.AutoValue;
import com.google.common.collect.ImmutableList;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;

import java.util.List;

import ch.alni.fido.uaf.metadata.v1_1.DisplayPNGCharacteristicsDescriptor;

@AutoValue
@JsonDeserialize(builder = AuthenticatorRegistrationAssertion.Builder.class)
public abstract class AuthenticatorRegistrationAssertion {
    public static Builder builder() {
        return new AutoValue_AuthenticatorRegistrationAssertion.Builder()
                .setTcDisplayPNGCharacteristics(ImmutableList.of())
                .setExtensions(ImmutableList.of());
    }

    @JsonGetter
    public abstract String assertionScheme();

    @JsonGetter
    public abstract String assertion();

    @JsonGetter
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public abstract ImmutableList<DisplayPNGCharacteristicsDescriptor> tcDisplayPNGCharacteristics();

    @JsonGetter("exts")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public abstract ImmutableList<Extension> extensions();

    @AutoValue.Builder
    @JsonPOJOBuilder(withPrefix = "set")
    public abstract static class Builder {
        @JsonCreator
        static Builder create() {
            return builder();
        }

        @JsonSetter
        public abstract Builder setAssertionScheme(String value);

        @JsonSetter
        public abstract Builder setAssertion(String value);

        @JsonSetter
        public abstract Builder setTcDisplayPNGCharacteristics(List<DisplayPNGCharacteristicsDescriptor> value);

        @JsonSetter("exts")
        public abstract Builder setExtensions(List<Extension> value);

        public abstract AuthenticatorRegistrationAssertion build();
    }

}
