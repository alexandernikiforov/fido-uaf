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

public final class UInts {

    private UInts() {
    }

    public static boolean isUInt16(int value) {
        return value >= 0 && value <= UInt16.MAX_UINT16;
    }

    public static boolean isUInt8(int value) {
        return value >= 0 && value <= UInt8.MAX_UINT8;
    }

    public static boolean isUInt32(long value) {
        return value >= 0 && value <= UInt32.MAX_UINT32;
    }

}
