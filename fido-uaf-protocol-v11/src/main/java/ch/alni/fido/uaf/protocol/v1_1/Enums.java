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
