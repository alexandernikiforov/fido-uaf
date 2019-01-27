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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.junit.Test;

import java.io.IOException;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

public class DeregisterAuthenticatorTest {

    @Test
    public void testDeserialization() throws IOException {
        final String json = "{\"aaid\": \"ABCD#ABCD\",\"keyID\": \"3287\"}";

        final DeregisterAuthenticator bean = new ObjectMapper()
                .readerFor(DeregisterAuthenticator.class)
                .readValue(json);

        assertThat(bean.aaid()).isEqualTo("ABCD#ABCD");
        assertThat(bean.keyId()).isEqualTo("3287");
    }

    @Test
    public void testSerialization() throws JsonProcessingException {
        final DeregisterAuthenticator bean = DeregisterAuthenticator.builder()
                .setAaid("ABCD#ABCD")
                .setKeyId("3287")
                .build();

        final String json = new ObjectMapper().writeValueAsString(bean);
        assertThat(json).containsPattern(Pattern.compile("\"aaid\"\\s*:\\s*\"ABCD#ABCD\""));
        assertThat(json).containsPattern(Pattern.compile("\"keyID\"\\s*:\\s*\"3287\""));
    }
}