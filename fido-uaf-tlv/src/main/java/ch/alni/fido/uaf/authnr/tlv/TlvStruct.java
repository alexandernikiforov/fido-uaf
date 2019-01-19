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

/**
 * Base class for the tags.
 */
public abstract class TlvStruct {
    private final UInt16 tag;
    private final UInt16 length;
    private final int lengthAsInt;

    private final int position;

    TlvStruct(int position, UInt16 tag, UInt16 length) {
        this.tag = tag;
        this.length = length;
        this.position = position;
        this.lengthAsInt = length.getValue();
    }

    public UInt16 getTag() {
        return tag;
    }

    public int getLengthAsInt() {
        return lengthAsInt;
    }

    public int getPosition() {
        return position;
    }

    public UInt16 getLength() {
        return length;
    }
}
