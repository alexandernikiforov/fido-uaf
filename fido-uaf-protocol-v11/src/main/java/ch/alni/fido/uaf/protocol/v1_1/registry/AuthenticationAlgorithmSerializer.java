package ch.alni.fido.uaf.protocol.v1_1.registry;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

import java.io.IOException;

import ch.alni.fido.registry.v1_1.SignatureAlgAndEncoding;

/**
 * TODO: javadoc
 */
public class AuthenticationAlgorithmSerializer extends JsonSerializer<SignatureAlgAndEncoding> {

    @Override
    public void serialize(SignatureAlgAndEncoding value, JsonGenerator gen, SerializerProvider serializers) throws IOException {
        gen.writeNumber(value.getCode());
    }
}
