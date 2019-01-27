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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;

import java.util.List;

@AutoValue
@JsonDeserialize(builder = AuthenticationRequest.Builder.class)
public abstract class AuthenticationRequest {
    public static Builder builder() {
        return new AutoValue_AuthenticationRequest.Builder()
                .setTransactions(ImmutableList.of());
    }

    @JsonGetter
    public abstract OperationHeader header();

    @JsonGetter
    public abstract String challenge();

    @JsonGetter("transaction")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public abstract ImmutableList<Transaction> transactions();

    @JsonGetter
    public abstract Policy policy();

    @AutoValue.Builder
    @JsonPOJOBuilder(withPrefix = "set")
    public abstract static class Builder {
        @JsonCreator
        static Builder create() {
            return AuthenticationRequest.builder();
        }

        @JsonSetter
        public abstract Builder setHeader(OperationHeader value);

        @JsonSetter
        public abstract Builder setChallenge(String value);

        @JsonSetter("transaction")
        public abstract Builder setTransactions(List<Transaction> value);

        @JsonSetter
        public abstract Builder setPolicy(Policy value);

        public abstract AuthenticationRequest build();
    }
}