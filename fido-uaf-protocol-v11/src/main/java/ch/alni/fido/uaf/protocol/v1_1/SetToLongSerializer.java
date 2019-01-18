package ch.alni.fido.uaf.protocol.v1_1;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

import java.io.IOException;
import java.util.Set;

abstract class SetToLongSerializer<T> extends JsonSerializer<Set<T>> {

    @Override
    public void serialize(Set<T> set, JsonGenerator gen, SerializerProvider serializers) throws IOException {
        final long value = set.stream()
                .mapToLong(this::setValueToLong)
                .reduce(0, (result, val) -> result | val);

        gen.writeNumber(value);
    }

    @Override
    public boolean isEmpty(SerializerProvider provider, Set<T> value) {
        return null == value || value.isEmpty();
    }

    abstract long setValueToLong(T setValue);
}
