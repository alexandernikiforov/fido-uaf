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

package ch.alni.fido.uaf.protocol.v1_1.registry;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;

import java.io.IOException;

import ch.alni.fido.registry.v1_1.SignatureAlgAndEncoding;

/**
 * TODO: javadoc
 */
public class AuthenticationAlgorithmDeserializer extends JsonDeserializer<SignatureAlgAndEncoding> {

    @Override
    public SignatureAlgAndEncoding deserialize(JsonParser p, DeserializationContext ctxt) throws IOException, JsonProcessingException {
        final Number numberValue = p.getNumberValue();
        if (null != numberValue) {
            return SignatureAlgAndEncoding.fromCode(numberValue.intValue());
        }
        else {
            return null;
        }
    }
}
