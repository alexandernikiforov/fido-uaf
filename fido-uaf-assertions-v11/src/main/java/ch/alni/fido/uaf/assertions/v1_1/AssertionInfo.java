package ch.alni.fido.uaf.assertions.v1_1;

import com.google.auto.value.AutoValue;
import com.google.common.base.Preconditions;

import ch.alni.fido.registry.v1_1.PublicKeyAlgAndEncoding;
import ch.alni.fido.registry.v1_1.SignatureAlgAndEncoding;
import ch.alni.fido.uaf.authnr.tlv.UInts;

@AutoValue
public abstract class AssertionInfo {
    public static Builder builder() {
        return new AutoValue_AssertionInfo.Builder();
    }

    public abstract int authenticatorVersion();

    public abstract int authenticationMode();

    public abstract SignatureAlgAndEncoding signatureAlgAndEncoding();

    public abstract PublicKeyAlgAndEncoding publicKeyAlgAndEncoding();

    @AutoValue.Builder
    public abstract static class Builder {
        public abstract Builder setAuthenticatorVersion(int value);

        public abstract Builder setAuthenticationMode(int value);

        public abstract Builder setSignatureAlgAndEncoding(SignatureAlgAndEncoding value);

        public abstract Builder setPublicKeyAlgAndEncoding(PublicKeyAlgAndEncoding value);

        abstract AssertionInfo autoBuild();

        public AssertionInfo build() {
            AssertionInfo assertionInfo = autoBuild();

            Preconditions.checkState(UInts.isUInt8(assertionInfo.authenticationMode()), "authenticationMode must be UINT8");
            Preconditions.checkState(UInts.isUInt16(assertionInfo.authenticatorVersion()), "authenticatorVersion must be UINT16");

            return assertionInfo;
        }
    }
}
