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

package ch.alni.fido.uaf.protocol.v1_1.registry;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

import java.io.IOException;
import java.util.Set;

abstract class SetToIntSerializer<T> extends JsonSerializer<Set<T>> {

    @Override
    public void serialize(Set<T> set, JsonGenerator gen, SerializerProvider serializers) throws IOException {
        final int value = set.stream()
                .mapToInt(this::setValueToInt)
                .reduce(0, (result, val) -> result | val);

        gen.writeNumber(value);
    }

    @Override
    public boolean isEmpty(SerializerProvider provider, Set<T> value) {
        return null == value || value.isEmpty();
    }

    abstract int setValueToInt(T setValue);
}
