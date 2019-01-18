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

public class RegistrationResponseTest {

    @Test
    public void testReadRequest() throws Exception {
        final String regResponseAsJson = IOUtils.toString(
                getClass().getResourceAsStream("/registration_response.json"),
                StandardCharsets.UTF_8
        );

        final List<RegistrationResponse> list = new ObjectMapper().readValue(
                regResponseAsJson,
                new TypeReference<List<RegistrationResponse>>() {
                }
        );

        assertThat(list).hasSize(1);
        assertThat(list.get(0)).isInstanceOf(RegistrationResponse.class);

        final RegistrationResponse response = list.get(0);
        assertThat(response.header().op()).isEqualByComparingTo(Operation.REG);

        final String json = new ObjectMapper().writeValueAsString(Collections.singletonList(response));
        assertThat(json)
                .containsPattern(Pattern.compile("\"op\"\\s*:\\s*\"Reg\""))
                .doesNotContain("null")
        ;
    }
}