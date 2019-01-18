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

package ch.alni.fido.uaf.authnr.tlv.types;

/**
 * Representation of a UINT16 value.
 */
public class UInt16 {
    private final byte low;
    private final byte high;

    private final int value;

    public UInt16(byte low, byte high) {
        this.low = low;
        this.high = high;

        this.value = high * 256 + low;
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
}
