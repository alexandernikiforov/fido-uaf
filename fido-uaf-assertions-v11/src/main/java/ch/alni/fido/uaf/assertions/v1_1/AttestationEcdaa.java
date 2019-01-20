package ch.alni.fido.uaf.assertions.v1_1;

import com.google.auto.value.AutoValue;

@AutoValue
public abstract class AttestationEcdaa {
    public static AttestationEcdaa ofSignature(byte[] value) {
        return new AutoValue_AttestationEcdaa(value);
    }

    @SuppressWarnings("mutable")
    public abstract byte[] signature();
}
