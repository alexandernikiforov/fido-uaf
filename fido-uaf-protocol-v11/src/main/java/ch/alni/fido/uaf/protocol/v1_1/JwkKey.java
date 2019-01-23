package ch.alni.fido.uaf.protocol.v1_1;

import com.google.auto.value.AutoValue;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;

@AutoValue
@JsonDeserialize(builder = JwkKey.Builder.class)
public abstract class JwkKey {
    public static Builder builder() {
        return new AutoValue_JwkKey.Builder()
                .setKty("EC")
                .setCrv("P-256")
                ;
    }

    @JsonGetter
    public abstract String kty();

    @JsonGetter
    public abstract String crv();

    @JsonGetter
    public abstract String x();

    @JsonGetter
    public abstract String y();

    @AutoValue.Builder
    @JsonPOJOBuilder(withPrefix = "set")
    public abstract static class Builder {
        @JsonCreator
        static Builder create() {
            return builder();
        }

        @JsonSetter
        public abstract Builder setKty(String value);

        @JsonSetter
        public abstract Builder setCrv(String value);

        @JsonSetter
        public abstract Builder setX(String value);

        @JsonSetter
        public abstract Builder setY(String value);

        public abstract JwkKey build();
    }
}
