package ch.alni.fido.uaf.protocol.v1_1;

import com.google.auto.value.AutoValue;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import java.util.List;
import java.util.OptionalInt;
import java.util.Set;

import ch.alni.fido.registry.v1_1.AttachmentHint;
import ch.alni.fido.registry.v1_1.KeyProtection;
import ch.alni.fido.registry.v1_1.MatcherProtection;
import ch.alni.fido.registry.v1_1.SignatureAlgAndEncoding;
import ch.alni.fido.registry.v1_1.TransactionConfirmationDisplay;
import ch.alni.fido.registry.v1_1.UserVerificationMethod;
import ch.alni.fido.uaf.protocol.v1_1.registry.AttachmentHintSerializer;
import ch.alni.fido.uaf.protocol.v1_1.registry.AuthenticationAlgorithmDeserializer;
import ch.alni.fido.uaf.protocol.v1_1.registry.AuthenticationAlgorithmSerializer;
import ch.alni.fido.uaf.protocol.v1_1.registry.KeyProtectionSerializer;
import ch.alni.fido.uaf.protocol.v1_1.registry.MatcherProtectionSerializer;
import ch.alni.fido.uaf.protocol.v1_1.registry.UserVerificationMethodSerializer;

import static ch.alni.fido.uaf.protocol.v1_1.Enums.toBitValue;
import static ch.alni.fido.uaf.protocol.v1_1.Enums.toEnumSet;

@AutoValue
@JsonDeserialize(builder = MatchCriteria.Builder.class)
public abstract class MatchCriteria {
    public static Builder builder() {
        return new AutoValue_MatchCriteria.Builder()
                .setAaids(ImmutableList.of())
                .setVendorIds(ImmutableList.of())
                .setKeyIds(ImmutableList.of())

                .setUserVerificationAsLong(0)
                .setUserVerification(ImmutableSet.of())
                .setKeyProtectionAsInt(0)
                .setKeyProtection(ImmutableSet.of())
                .setMatcherProtectionAsInt(0)
                .setMatcherProtection(ImmutableSet.of())
                .setAttachmentHintAsInt(0)
                .setAttachmentHint(ImmutableSet.of())
                .setTcDisplayAsInt(0)
                .setTcDisplay(ImmutableSet.of())

                .setAuthenticationAlgorithms(ImmutableList.of())
                .setAssertionSchemes(ImmutableList.of())
                .setAttestationTypes(ImmutableList.of())
                .setExtensions(ImmutableList.of())
                .setAuthenticatorVersion(0)
                ;
    }

    @JsonGetter("aaid")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public abstract ImmutableList<String> aaids();

    @JsonGetter("vendorID")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public abstract ImmutableList<String> vendorIds();

    @JsonGetter("keyIDs")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public abstract ImmutableList<String> keyIds();

    @JsonGetter
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    @JsonSerialize(using = UserVerificationMethodSerializer.class)
    public abstract ImmutableSet<UserVerificationMethod> userVerification();

    abstract long userVerificationAsLong();

    @JsonGetter
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    @JsonSerialize(using = KeyProtectionSerializer.class)
    public abstract ImmutableSet<KeyProtection> keyProtection();

    abstract int keyProtectionAsInt();

    @JsonGetter
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    @JsonSerialize(using = MatcherProtectionSerializer.class)
    public abstract ImmutableSet<MatcherProtection> matcherProtection();

    abstract int matcherProtectionAsInt();

    @JsonGetter
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    @JsonSerialize(using = AttachmentHintSerializer.class)
    public abstract ImmutableSet<AttachmentHint> attachmentHint();

    abstract int attachmentHintAsInt();

    @JsonGetter
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public abstract ImmutableSet<TransactionConfirmationDisplay> tcDisplay();

    abstract int tcDisplayAsInt();

    @JsonGetter
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    @JsonSerialize(contentUsing = AuthenticationAlgorithmSerializer.class)
    @JsonDeserialize(contentUsing = AuthenticationAlgorithmDeserializer.class)
    public abstract ImmutableList<SignatureAlgAndEncoding> authenticationAlgorithms();

    @JsonGetter
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public abstract ImmutableList<String> assertionSchemes();

    @JsonGetter
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public abstract ImmutableList<AttestationType> attestationTypes();

    @JsonGetter
    @JsonInclude(JsonInclude.Include.NON_ABSENT)
    public abstract OptionalInt authenticatorVersion();

    @JsonGetter("exts")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public abstract ImmutableList<Extension> extensions();

    @AutoValue.Builder
    @JsonPOJOBuilder(withPrefix = "set")
    abstract public static class Builder {
        @JsonCreator
        static Builder create() {
            return builder();
        }

        @JsonSetter("aaid")
        public abstract Builder setAaids(List<String> value);

        @JsonSetter("vendorID")
        public abstract Builder setVendorIds(List<String> value);

        @JsonSetter("keyIDs")
        public abstract Builder setKeyIds(List<String> value);

        @JsonSetter("userVerification")
        abstract Builder setUserVerificationAsLong(long value);

        public abstract Builder setUserVerification(Set<UserVerificationMethod> value);

        @JsonSetter("keyProtection")
        abstract Builder setKeyProtectionAsInt(int value);

        public abstract Builder setKeyProtection(Set<KeyProtection> value);

        @JsonSetter("matcherProtection")
        abstract Builder setMatcherProtectionAsInt(int value);

        public abstract Builder setMatcherProtection(Set<MatcherProtection> value);

        @JsonSetter("attachmentHint")
        abstract Builder setAttachmentHintAsInt(int value);

        public abstract Builder setAttachmentHint(Set<AttachmentHint> value);

        @JsonSetter("tcDisplay")
        abstract Builder setTcDisplayAsInt(int value);

        public abstract Builder setTcDisplay(Set<TransactionConfirmationDisplay> value);

        @JsonSetter
        public abstract Builder setAuthenticationAlgorithms(List<SignatureAlgAndEncoding> value);

        @JsonSetter
        public abstract Builder setAssertionSchemes(List<String> value);

        @JsonSetter
        public abstract Builder setAttestationTypes(List<AttestationType> value);

        @JsonSetter
        public abstract Builder setAuthenticatorVersion(int value);

        @JsonSetter("exts")
        public abstract Builder setExtensions(List<Extension> value);

        abstract long userVerificationAsLong();

        abstract ImmutableSet<UserVerificationMethod> userVerification();

        abstract int keyProtectionAsInt();

        abstract ImmutableSet<KeyProtection> keyProtection();

        abstract int matcherProtectionAsInt();

        abstract ImmutableSet<MatcherProtection> matcherProtection();

        abstract int attachmentHintAsInt();

        abstract ImmutableSet<AttachmentHint> attachmentHint();

        abstract int tcDisplayAsInt();

        abstract ImmutableSet<TransactionConfirmationDisplay> tcDisplay();

        abstract MatchCriteria autoBuild();

        public MatchCriteria build() {
            if (userVerificationAsLong() != 0) {
                setUserVerification(toEnumSet(UserVerificationMethod.class, UserVerificationMethod::getCode, userVerificationAsLong()));
            }
            else {
                setUserVerificationAsLong(toBitValue(UserVerificationMethod::getCode, userVerification()));
            }
            if (keyProtectionAsInt() != 0) {
                setKeyProtection(toEnumSet(KeyProtection.class, KeyProtection::getCode, keyProtectionAsInt()));
            }
            else {
                setKeyProtectionAsInt(toBitValue(KeyProtection::getCode, keyProtection()));
            }
            if (matcherProtectionAsInt() != 0) {
                setMatcherProtection(toEnumSet(MatcherProtection.class, MatcherProtection::getCode, matcherProtectionAsInt()));
            }
            else {
                setMatcherProtectionAsInt(toBitValue(MatcherProtection::getCode, matcherProtection()));
            }
            if (attachmentHintAsInt() != 0) {
                setAttachmentHint(toEnumSet(AttachmentHint.class, AttachmentHint::getCode, attachmentHintAsInt()));
            }
            else {
                setAttachmentHintAsInt(toBitValue(AttachmentHint::getCode, attachmentHint()));
            }
            if (tcDisplayAsInt() != 0) {
                setTcDisplay(toEnumSet(TransactionConfirmationDisplay.class, TransactionConfirmationDisplay::getCode, tcDisplayAsInt()));
            }
            else {
                setTcDisplayAsInt(toBitValue(TransactionConfirmationDisplay::getCode, tcDisplay()));
            }

            return autoBuild();
        }
    }
}
