package ch.alni.fido.uaf.assertions.v1_1;

import com.google.auto.value.AutoValue;

@AutoValue
public abstract class AttestationBasicSurrogate {
    public static AttestationBasicSurrogate ofSignature(byte[] value) {
        return new AutoValue_AttestationBasicSurrogate(value);
    }

    @SuppressWarnings("mutable")
    public abstract byte[] signature();
}
