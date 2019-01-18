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
import java.util.Optional;

@AutoValue
@JsonDeserialize(builder = OperationHeader.Builder.class)
public abstract class OperationHeader {
    public static Builder builder() {
        return new AutoValue_OperationHeader.Builder()
                .setExtensions(ImmutableList.of());
    }

    @JsonGetter
    public abstract Version upv();

    @JsonGetter
    public abstract Operation op();

    @JsonGetter("appID")
    @JsonInclude(JsonInclude.Include.NON_ABSENT)
    public abstract Optional<String> appId();

    @JsonGetter
    @JsonInclude(JsonInclude.Include.NON_ABSENT)
    public abstract Optional<String> serverData();

    @JsonGetter("exts")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public abstract ImmutableList<Extension> extensions();

    @AutoValue.Builder
    @JsonPOJOBuilder(withPrefix = "set")
    public abstract static class Builder {

        @JsonCreator
        static Builder create() {
            return OperationHeader.builder();
        }

        @JsonSetter
        public abstract Builder setUpv(Version value);

        @JsonSetter
        public abstract Builder setOp(Operation value);

        @JsonSetter("appID")
        public abstract Builder setAppId(String value);

        @JsonSetter
        public abstract Builder setServerData(String value);

        @JsonSetter("exts")
        public abstract Builder setExtensions(List<Extension> extensionList);

        public abstract OperationHeader build();
    }
}
