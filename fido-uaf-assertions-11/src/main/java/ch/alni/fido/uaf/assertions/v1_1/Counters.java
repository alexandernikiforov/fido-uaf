package ch.alni.fido.uaf.assertions.v1_1;

import com.google.auto.value.AutoValue;

@AutoValue
public abstract class Counters {
    public static Builder builder() {
        return new AutoValue_Counters.Builder();
    }

    public abstract long signatureCounter();

    public abstract long registrationCounter();

    @AutoValue.Builder
    public abstract static class Builder {
        public abstract Builder setSignatureCounter(long value);

        public abstract Builder setRegistrationCounter(long value);

        public abstract Counters build();
    }

}
