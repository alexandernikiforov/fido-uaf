package ch.alni.fido.uaf.protocol.v1_1;

import com.google.auto.value.AutoValue;
import com.google.common.collect.ImmutableList;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

import java.util.Collection;

@AutoValue
public abstract class MatchCriteriaAlternative {

    @JsonCreator
    public static MatchCriteriaAlternative of(Collection<? extends MatchCriteria> collection) {
        return new AutoValue_MatchCriteriaAlternative(ImmutableList.copyOf(collection));
    }

    @JsonValue
    public abstract ImmutableList<MatchCriteria> criteria();
}
