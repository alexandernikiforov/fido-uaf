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

package ch.alni.fido.uaf.transport.https.v1_1;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public enum TokenType {
    HTTP_COOKIE("HTTP_COOKIE"),
    OAUTH("OAUTH"),
    OAUTH2("OAUTH2"),
    SAML1_1("SAML1_1"),
    SAML2("SAML2"),
    JWT("JWT"),
    OPENID_CONNECT("OPENID_CONNECT");

    private final static Map<String, TokenType> VALUE_MAP =
            Stream.of(values()).collect(Collectors.toMap(
                    TokenType::getValue,
                    Function.identity()
            ));

    private final String value;

    TokenType(String value) {
        this.value = value;
    }

    @JsonCreator
    public static TokenType fromValue(String value) {
        return Optional.ofNullable(VALUE_MAP.get(value))
                .orElseThrow(() -> new IllegalArgumentException("invalid value " + value));
    }

    @JsonValue
    public String getValue() {
        return value;
    }

}
