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

import org.apache.commons.io.IOUtils;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

public class DeregistrationRequestTest {

    @Test
    public void testReadRequest() throws Exception {
        final String deregRequestAsJson = IOUtils.toString(
                getClass().getResourceAsStream("/deregistration_request.json"),
                StandardCharsets.UTF_8
        );

        final List<DeregistrationRequest> list = new ObjectMapper().readValue(
                deregRequestAsJson,
                new TypeReference<List<DeregistrationRequest>>() {
                }
        );

        assertThat(list).hasSize(1);
        assertThat(list.get(0)).isInstanceOf(DeregistrationRequest.class);

        final DeregistrationRequest request = list.get(0);
        assertThat(request.header().op()).isEqualByComparingTo(Operation.DEREG);

        final String json = new ObjectMapper().writeValueAsString(request);
        assertThat(json)
                .containsPattern(Pattern.compile("\"op\"\\s*:\\s*\"Dereg\""))
                .doesNotContain("null")
        ;
    }
}