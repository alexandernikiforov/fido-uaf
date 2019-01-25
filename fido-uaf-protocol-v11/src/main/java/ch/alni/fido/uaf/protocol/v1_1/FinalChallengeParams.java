package ch.alni.fido.uaf.protocol.v1_1;

import com.google.auto.value.AutoValue;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;

@AutoValue
@JsonDeserialize(builder = FinalChallengeParams.Builder.class)
public abstract class FinalChallengeParams {
    static Builder builder() {
        return new AutoValue_FinalChallengeParams.Builder();
    }

    @JsonGetter("appID")
    public abstract String appId();

    @JsonGetter
    public abstract String challenge();

    @JsonGetter("facetID")
    public abstract String facetId();

    @JsonGetter
    public abstract ChannelBinding channelBinding();

    @AutoValue.Builder
    @JsonPOJOBuilder(withPrefix = "set")
    abstract static class Builder {
        @JsonCreator
        static Builder create() {
            return builder();
        }

        @JsonSetter("appID")
        public abstract Builder setAppId(String value);

        @JsonSetter
        public abstract Builder setChallenge(String value);

        @JsonSetter("facetID")
        public abstract Builder setFacetId(String value);

        @JsonSetter
        public abstract Builder setChannelBinding(ChannelBinding value);

        abstract FinalChallengeParams build();
    }
}
