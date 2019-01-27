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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public enum AttestationType {

    TAG_ATTESTATION_BASIC_FULL(0x3E07),
    TAG_ATTESTATION_BASIC_SURROGATE(0x3E08),
    TAG_ATTESTATION_ECDAA(0x3E09);

    private final static Map<Integer, AttestationType> VALUE_MAP =
            Stream.of(values()).collect(Collectors.toMap(
                    AttestationType::getCode,
                    Function.identity()
            ));
    private final int code;

    AttestationType(int code) {
        this.code = code;
    }

    @JsonCreator
    public static AttestationType fromCode(int code) {
        return Optional.ofNullable(VALUE_MAP.get(code))
                .orElseThrow(() -> new IllegalArgumentException("invalid value " + code));
    }

    @JsonValue
    public int getCode() {
        return code;
    }
}
