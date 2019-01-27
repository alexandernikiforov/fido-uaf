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

package ch.alni.fido.uaf.authnr.tlv;

import com.google.common.base.Objects;
import com.google.common.base.Preconditions;

/**
 * Representation of a UINT16 value.
 */
public final class UInt8 implements TagValue {
    public static final int MAX_UINT8 = 0xff;

    private final byte low;
    private final int value;

    private UInt8(int value) {
        this.value = value;
        this.low = (byte) (value & 0x00ff);
    }

    public static UInt8 of(int value) {
        Preconditions.checkArgument(UInts.isUInt8(value), value + " is not UINT8");
        return new UInt8(value);
    }

    public byte getLow() {
        return low;
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
        UInt8 uInt8 = (UInt8) o;
        return value == uInt8.value;
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(value);
    }

    @Override
    public int length() {
        return 1;
    }

    @Override
    public byte[] toByteArray() {
        return new byte[]{low};
    }
}
