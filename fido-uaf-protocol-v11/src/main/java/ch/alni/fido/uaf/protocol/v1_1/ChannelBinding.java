package ch.alni.fido.uaf.protocol.v1_1;

import com.google.auto.value.AutoValue;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;

import java.util.Optional;

@AutoValue
@JsonDeserialize(builder = ChannelBinding.Builder.class)
public abstract class ChannelBinding {
    public static Builder builder() {
        return new AutoValue_ChannelBinding.Builder();
    }

    @JsonGetter
    @JsonInclude(JsonInclude.Include.NON_ABSENT)
    public abstract Optional<String> serverEndPoint();

    @JsonGetter
    @JsonInclude(JsonInclude.Include.NON_ABSENT)
    public abstract Optional<String> tlsServerCertificate();

    @JsonGetter
    @JsonInclude(JsonInclude.Include.NON_ABSENT)
    public abstract Optional<String> tlsUnique();

    @JsonGetter
    @JsonInclude(JsonInclude.Include.NON_ABSENT)
    public abstract Optional<String> cidPubkey();

    @AutoValue.Builder
    @JsonPOJOBuilder(withPrefix = "set")
    public abstract static class Builder {
        @JsonCreator
        static Builder create() {
            return builder();
        }

        @JsonSetter
        public abstract Builder setServerEndPoint(String value);

        @JsonSetter
        public abstract Builder setTlsServerCertificate(String value);

        @JsonSetter
        public abstract Builder setTlsUnique(String value);

        @JsonSetter
        public abstract Builder setCidPubkey(String value);

        public abstract ChannelBinding build();
    }
}
