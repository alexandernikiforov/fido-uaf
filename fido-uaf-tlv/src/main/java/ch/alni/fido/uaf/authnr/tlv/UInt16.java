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

import com.google.common.base.Objects;
import com.google.common.base.Preconditions;

/**
 * Representation of a UINT16 value.
 */
public final class UInt16 {
    public static final int MAX_UINT16 = 0xffff;

    private final byte low;
    private final byte high;
    private final int value;

    private UInt16(byte low, byte high) {
        this.low = low;
        this.high = high;
        this.value = (high & 0xff) << 8 | (low & 0x00ff);
    }

    private UInt16(int value) {
        this.value = value;
        this.low = (byte) (value & 0x00ff);
        this.high = (byte) (value >> 8 & 0x00ff);
    }

    public static UInt16 of(int value) {
        Preconditions.checkArgument(UInts.isUInt16(value), value + " is not UINT16");
        return new UInt16(value);
    }

    public static UInt16 of(byte low, byte high) {
        return new UInt16(low, high);
    }

    public byte getLow() {
        return low;
    }

    public byte getHigh() {
        return high;
    }

    public int getValue() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        UInt16 uInt16 = (UInt16) o;
        return value == uInt16.value;
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(value);
    }
}
