/*
 *      FIDO UAF 1.1 Protocol and Assertion Parser Support
 *      Copyright (C) 2019  Alexander Nikiforov
 *
 *      This program is free software: you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation, either version 3 of the License, or
 *      (at your option) any later version.
 *
 *      This program is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *      GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU General Public License
 *      along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

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
import ch.alni.fido.uaf.protocol.v1_1.registry.TransactionConfirmationDisplaySerializer;
import ch.alni.fido.uaf.protocol.v1_1.registry.UserVerificationMethodSerializer;

import static ch.alni.fido.uaf.protocol.v1_1.Enums.toBitValue;
import static ch.alni.fido.uaf.protocol.v1_1.Enums.toEnumSet;

@AutoValue
@JsonDeserialize(builder = MatchCriteria.Builder.class)
public abstract class MatchCriteria {
    public static Builder builder() {
        return new AutoValue_MatchCriteria.Builder()
                .setAaids(ImmutableSet.of())
                .setVendorIds(ImmutableSet.of())
                .setKeyIds(ImmutableSet.of())

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
                ;
    }

    @JsonGetter("aaid")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public abstract ImmutableSet<String> aaids();

    @JsonGetter("vendorID")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public abstract ImmutableSet<String> vendorIds();

    @JsonGetter("keyIDs")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public abstract ImmutableSet<String> keyIds();

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
    @JsonSerialize(using = TransactionConfirmationDisplaySerializer.class)
    public abstract ImmutableSet<TransactionConfirmationDisplay> tcDisplay();

    abstract int tcDisplayAsInt();

    @JsonGetter
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    @JsonSerialize(contentUsing = AuthenticationAlgorithmSerializer.class)
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
        public abstract Builder setAaids(Set<String> value);

        @JsonSetter("vendorID")
        public abstract Builder setVendorIds(Set<String> value);

        @JsonSetter("keyIDs")
        public abstract Builder setKeyIds(Set<String> value);

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
        @JsonDeserialize(contentUsing = AuthenticationAlgorithmDeserializer.class)
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
