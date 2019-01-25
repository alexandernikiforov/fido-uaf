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

public class RegistrationRequestTest {

    @Test
    public void testReadRequest() throws Exception {
        final String regRequestAsJson = IOUtils.toString(
                getClass().getResourceAsStream("/registration_request.json"),
                StandardCharsets.UTF_8
        );

        final List<RegistrationRequest> list = new ObjectMapper().readValue(
                regRequestAsJson,
                new TypeReference<List<RegistrationRequest>>() {
                }
        );

        assertThat(list).hasSize(1);
        assertThat(list.get(0)).isInstanceOf(RegistrationRequest.class);

        final RegistrationRequest request = list.get(0);
        assertThat(request.header().op()).isEqualByComparingTo(Operation.REG);

        final String json = new ObjectMapper()
                .registerModule(new Jdk8Module())
                .registerModule(new JavaTimeModule())
                .writeValueAsString(Collections.singletonList(request));
        assertThat(json)
                .containsPattern(Pattern.compile("\"op\"\\s*:\\s*\"Reg\""))
                .doesNotContain("null")
        ;
    }
}