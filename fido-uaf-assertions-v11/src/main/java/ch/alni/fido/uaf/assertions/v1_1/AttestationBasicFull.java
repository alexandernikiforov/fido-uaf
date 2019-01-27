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