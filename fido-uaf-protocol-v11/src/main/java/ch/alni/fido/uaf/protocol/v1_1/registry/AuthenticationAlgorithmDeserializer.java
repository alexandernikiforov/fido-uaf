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
