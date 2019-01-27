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

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import org.apache.commons.io.IOUtils;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

public class AuthenticationRequestTest {

    @Test
    public void testReadRequest() throws Exception {
        final String authRequestAsJson = IOUtils.toString(
                getClass().getResourceAsStream("/authentication_request.json"),
                StandardCharsets.UTF_8
        );

        final List<AuthenticationRequest> list = new ObjectMapper().readValue(
                authRequestAsJson,
                new TypeReference<List<AuthenticationRequest>>() {
                }
        );

        assertThat(list).hasSize(1);
        assertThat(list.get(0)).isInstanceOf(AuthenticationRequest.class);

        final AuthenticationRequest request = list.get(0);
        assertThat(request.header().op()).isEqualByComparingTo(Operation.AUTH);

        final String json = new ObjectMapper()
                .registerModule(new Jdk8Module())
                .registerModule(new JavaTimeModule())
                .writeValueAsString(Collections.singletonList(request));

        assertThat(json)
                .containsPattern(Pattern.compile("\"op\"\\s*:\\s*\"Auth\""))
                .doesNotContain("null")
        ;
    }
}