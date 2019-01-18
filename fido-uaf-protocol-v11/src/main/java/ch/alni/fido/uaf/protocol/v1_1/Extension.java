package ch.alni.fido.uaf.protocol.v1_1;

import com.google.auto.value.AutoValue;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;

@AutoValue
@JsonDeserialize(builder = Extension.Builder.class)
public abstract class Extension {
    static Builder builder() {
        return new AutoValue_Extension.Builder();
    }

    @JsonGetter
    public abstract String id();

    @JsonGetter
    public abstract String data();

    @JsonGetter("fail_if_unknown")
    public abstract boolean failIfUnknown();

    @AutoValue.Builder
    @JsonPOJOBuilder(withPrefix = "set")
    abstract static class Builder {
        @JsonCreator
        static Builder create() {
            return Extension.builder();
        }

        @JsonSetter
        abstract Builder setId(String value);

        @JsonSetter
        abstract Builder setData(String value);

        @JsonSetter("fail_if_unknown")
        abstract Builder setFailIfUnknown(boolean value);

        abstract Extension build();
    }
}
