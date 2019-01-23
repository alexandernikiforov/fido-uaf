package ch.alni.fido.uaf;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.List;

public final class Json {

    private Json() {
    }

    public static <T> String toJsonString(T object) {
        try {
            return new ObjectMapper().writeValueAsString(object);
        }
        catch (JsonProcessingException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static <T> List<T> ofJsonString(String jsonString) {
        try {
            return new ObjectMapper().readValue(jsonString, new TypeReference<List<T>>() {
            });
        }
        catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

}
