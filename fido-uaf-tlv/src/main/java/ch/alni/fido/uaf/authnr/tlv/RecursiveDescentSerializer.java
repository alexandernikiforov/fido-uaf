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

public class RecursiveDescentSerializer implements TlvSerializer {

    @Override
    public byte[] toByteArray(TlvStruct tlvStruct) {
        if (null == tlvStruct) {
            throw new IllegalArgumentException("cannot serialize a null TLV structure");
        }

        return new Serializer().serializeTlv(tlvStruct);
    }

    private static class Serializer {
        private byte[] buffer;

        // we begin with nothing
        private int position = 0;

        private byte[] serializeTlv(TlvStruct tlvStruct) {
            buffer = new byte[tlvStruct.length() + 4];

            serializeTag(tlvStruct);

            return buffer;
        }

        private void serializeTag(TlvStruct tlvStruct) {
            if (tlvStruct.composite()) {
                serializeCompositeTag(tlvStruct);
            }
            else {
                serializeSingleTag(tlvStruct);
            }
        }

        private void serializeCompositeTag(TlvStruct compositeTag) {
            writeUInt16(compositeTag.tag());
            writeUInt16(compositeTag.length());
            compositeTag.tags().forEach(this::serializeTag);
        }

        private void serializeSingleTag(TlvStruct tlvStruct) {
            writeUInt16(tlvStruct.tag());
            writeUInt16(tlvStruct.length());
            tlvStruct.data().ifPresent(this::writeData);
        }

        private void writeData(ImmutableByteArray uInt8Array) {
            byte[] data = uInt8Array.toByteArray();
            System.arraycopy(data, 0, buffer, position, data.length);
            position += data.length;
        }

        private void writeUInt16(int value) {
            final UInt16 uInt16 = UInt16.of(value);
            // low
            buffer[position++] = uInt16.getLow();
            // high
            buffer[position++] = uInt16.getHigh();
        }
    }
}
