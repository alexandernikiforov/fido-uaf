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
public final class UInt32 implements TagValue {
    public static final long MAX_UINT32 = 0x7fffffff;

    private final byte byte0;
    private final byte byte1;
    private final byte byte2;
    private final byte byte3;

    private final long value;

    private UInt32(byte byte0, byte byte1, byte byte2, byte byte3) {
        this.byte0 = byte0;
        this.byte1 = byte1;
        this.byte2 = byte2;
        this.byte3 = byte3;

        this.value = (byte3 & 0xff) << 24 | (byte2 & 0x00ff) << 16 | (byte1 & 0xff) << 8 | (byte0 & 0x00ff);
    }

    private UInt32(long value) {
        this.value = value;
        this.byte0 = (byte) (value & 0x00ff);
        this.byte1 = (byte) (value >> 8 & 0x00ff);
        this.byte2 = (byte) (value >> 16 & 0x00ff);
        this.byte3 = (byte) (value >> 24 & 0x00ff);
    }

    public static UInt32 of(long value) {
        Preconditions.checkArgument(UInts.isUInt32(value), value + " is not UINT32");
        return new UInt32(value);
    }

    public static UInt32 of(byte byte0, byte byte1, byte byte2, byte byte3) {
        Preconditions.checkArgument(byte3 >= 0, "unsigned longs are not supported yet");
        return new UInt32(byte0, byte1, byte2, byte3);
    }

    public byte getByte0() {
        return byte0;
    }

    public byte getByte1() {
        return byte1;
    }

    public byte getByte2() {
        return byte2;
    }

    public byte getByte3() {
        return byte3;
    }

    public long getValue() {
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
        UInt32 uInt32 = (UInt32) o;
        return value == uInt32.value;
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(value);
    }

    @Override
    public int length() {
        return 4;
    }

    @Override
    public byte[] toByteArray() {
        return new byte[]{byte0, byte1, byte2, byte3};
    }
}
