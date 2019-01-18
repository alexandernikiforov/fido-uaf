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

@AutoValue
@JsonDeserialize(builder = Policy.Builder.class)
public abstract class Policy {
    static Builder builder() {
        return new AutoValue_Policy.Builder()
                .setDisallowed(ImmutableList.of());
    }

    @JsonGetter
    public abstract ImmutableList<MatchCriteriaAlternative> accepted();

    @JsonGetter
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public abstract List<MatchCriteria> disallowed();

    @AutoValue.Builder
    @JsonPOJOBuilder(withPrefix = "set")
    abstract static class Builder {
        @JsonCreator
        static Builder create() {
            return builder();
        }

        @JsonSetter
        public abstract Builder setAccepted(List<MatchCriteriaAlternative> value);

        @JsonSetter
        public abstract Builder setDisallowed(List<MatchCriteria> value);

        public abstract Policy build();
    }
}
