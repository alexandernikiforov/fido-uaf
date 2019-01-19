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
 * Single tag that does not have any children.
 */
public class SingleTag extends TlvStruct {
    private final byte[] data;

    public SingleTag(int position, UInt16 tag, UInt16 length, byte[] data) {
        super(position, tag, length);

        if (0 != (tag.getValue() & 0x1000)) {
            throw new IllegalArgumentException("provided tag is a composite, and not single: " + tag);
        }

        this.data = data;
    }

    public byte[] getData() {
        return data;
    }
}
