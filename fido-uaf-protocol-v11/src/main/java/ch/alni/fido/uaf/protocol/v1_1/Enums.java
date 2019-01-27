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

package ch.alni.fido.uaf.protocol.v1_1;

import java.util.EnumSet;
import java.util.Set;
import java.util.function.ToIntFunction;
import java.util.function.ToLongFunction;
import java.util.stream.Collectors;

final class Enums {
    private Enums() {
    }

    static <T extends Enum<T>> EnumSet<T> toEnumSet(Class<T> clazz, ToIntFunction<T> bitValueConverter, int bitValue) {
        return EnumSet.allOf(clazz).stream()
                .filter(enumValue -> (bitValueConverter.applyAsInt(enumValue) & bitValue) > 0)
                .collect(Collectors.toCollection(() -> EnumSet.noneOf(clazz)));
    }

    static <T extends Enum<T>> EnumSet<T> toEnumSet(Class<T> clazz, ToLongFunction<T> bitValueConverter, long bitValue) {
        return EnumSet.allOf(clazz).stream()
                .filter(enumValue -> (bitValueConverter.applyAsLong(enumValue) & bitValue) > 0)
                .collect(Collectors.toCollection(() -> EnumSet.noneOf(clazz)));
    }

    static <T extends Enum<T>> long toBitValue(ToLongFunction<T> bitValueConverter, Set<T> enumSet) {
        return enumSet.stream()
                .mapToLong(bitValueConverter)
                .reduce(0, (result, value) -> result | value);
    }

    static <T extends Enum<T>> int toBitValue(ToIntFunction<T> bitValueConverter, Set<T> enumSet) {
        return enumSet.stream()
                .mapToInt(bitValueConverter)
                .reduce(0, (result, value) -> result | value);
    }

}
