package ch.alni.fido.uaf.protocol.v1_1;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.commons.io.IOUtils;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

public class AuthenticationResponseTest {

    @Test
    public void testReadRequest() throws Exception {
        final String authResponseAsJson = IOUtils.toString(
                getClass().getResourceAsStream("/authentication_response.json"),
                StandardCharsets.UTF_8
        );

        final List<AuthenticationResponse> list = new ObjectMapper().readValue(
                authResponseAsJson,
                new TypeReference<List<AuthenticationResponse>>() {
                }
        );

        assertThat(list).hasSize(1);
        assertThat(list.get(0)).isInstanceOf(AuthenticationResponse.class);

        final AuthenticationResponse response = list.get(0);
        assertThat(response.header().op()).isEqualByComparingTo(Operation.AUTH);

        final String json = new ObjectMapper().writeValueAsString(Collections.singletonList(response));
        assertThat(json)
                .containsPattern(Pattern.compile("\"op\"\\s*:\\s*\"Auth\""))
                .doesNotContain("null")
        ;
    }
}