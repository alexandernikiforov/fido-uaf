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