/*
 *      FIDO UAF 1.1 Assertions Generator and Parser
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

package ch.alni.fido.uaf.authnr.tlv;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

/**
 * Convenience utility methods to build TLV structures.
 */
public final class TlvStructs {

    private TlvStructs() {
    }

    public static SingleTag createSingleTag(UInt16 tag, byte[] data) {
        return tlvStruct(tag, data).apply(0);
    }

    @SafeVarargs
    public static CompositeTag createCompositeTag(UInt16 tag, Function<Integer, ? extends TlvStruct>... builders) {
        if (null == builders) {
            throw new IllegalArgumentException("at least one child TLV struct must be passed as parameter");
        }

        return tlvStruct(tag, builders).apply(0);
    }

    @SafeVarargs
    public static Function<Integer, CompositeTag> tlvStruct(UInt16 tag, Function<Integer, ? extends TlvStruct>... builders) {
        return position -> {
            final List<TlvStruct> tlvStructList = new ArrayList<>(builders.length);

            int currentPosition = position;

            for (Function<Integer, ? extends TlvStruct> builder : builders) {
                TlvStruct tlvStruct = builder.apply(currentPosition);
                // change position for the next tag
                currentPosition += tlvStruct.getLengthAsInt() + 4;
                tlvStructList.add(tlvStruct);
            }

            return new CompositeTag(position, tag, UInt16.of(currentPosition - position), tlvStructList);
        };
    }

    public static Function<Integer, SingleTag> tlvStruct(UInt16 tag, byte[] data) {
        if (null == data || data.length == 0) {
            throw new IllegalArgumentException("cannot create a single tag with null or empty data");
        }

        return position -> new SingleTag(position, tag, UInt16.of(data.length), data);
    }
}
