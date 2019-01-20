package ch.alni.fido.uaf.assertions.v1_1;

import com.google.auto.value.AutoValue;

import java.security.cert.X509Certificate;

@AutoValue
public abstract class AttestationBasicFull {
    public static Builder builder() {
        return new AutoValue_AttestationBasicFull.Builder();
    }

    @SuppressWarnings("mutable")
    public abstract byte[] signature();

    public abstract X509Certificate certificate();

    @AutoValue.Builder
    public abstract static class Builder {
        public abstract Builder setSignature(byte[] value);

        public abstract Builder setCertificate(X509Certificate value);

        public abstract AttestationBasicFull build();
    }
}