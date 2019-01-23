package ch.alni.fido.uaf.protocol.v1_1;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.commons.io.IOUtils;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

import ch.alni.fido.uaf.Json;

import static org.assertj.core.api.Assertions.assertThat;

public class AuthenticationRequestTest {

    @Test
    public void testReadRequest() throws Exception {
        final String authRequestAsJson = IOUtils.toString(
                getClass().getResourceAsStream("/authentication_request.json"),
                StandardCharsets.UTF_8
        );

//        final List<AuthenticationRequest> list = new ObjectMapper().readValue(
//                authRequestAsJson,
//                new TypeReference<List<AuthenticationRequest>>() {}
//        );
        final List<AuthenticationRequest> list = Json.ofJsonString(authRequestAsJson);

        assertThat(list).hasSize(1);
        assertThat(list.get(0)).isInstanceOf(AuthenticationRequest.class);

        final AuthenticationRequest request = list.get(0);
        assertThat(request.header().op()).isEqualByComparingTo(Operation.AUTH);

        final String json = new ObjectMapper().writeValueAsString(Collections.singletonList(request));
        assertThat(json)
                .containsPattern(Pattern.compile("\"op\"\\s*:\\s*\"Auth\""))
                .doesNotContain("null")
        ;
    }
}