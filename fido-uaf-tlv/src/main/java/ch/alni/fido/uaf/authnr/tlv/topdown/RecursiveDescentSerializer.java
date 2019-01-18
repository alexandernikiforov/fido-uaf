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

package ch.alni.fido.uaf.authnr.tlv.topdown;

import ch.alni.fido.uaf.authnr.tlv.CompositeTag;
import ch.alni.fido.uaf.authnr.tlv.SingleTag;
import ch.alni.fido.uaf.authnr.tlv.TlvSerializer;
import ch.alni.fido.uaf.authnr.tlv.TlvStruct;

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
            buffer = new byte[tlvStruct.getLength() + 4];

            serializeTag(tlvStruct);

            return buffer;
        }

        private void serializeTag(TlvStruct tlvStruct) {
            if (tlvStruct instanceof CompositeTag) {
                serializeCompositeTag((CompositeTag) tlvStruct);
            }
            else {
                serializeSingleTag((SingleTag) tlvStruct);
            }
        }

        private void serializeCompositeTag(CompositeTag compositeTag) {
            writeUInt16(compositeTag.getTag());
            writeUInt16(compositeTag.getLength());

            compositeTag.getTags().forEach(this::serializeTag);
        }

        private void serializeSingleTag(SingleTag tlvStruct) {
            writeUInt16(tlvStruct.getTag());
            writeUInt16(tlvStruct.getLength());
            writeData(tlvStruct.getData());
        }

        private void writeData(byte[] data) {
            System.arraycopy(data, 0, buffer, position, data.length);
            position += data.length;
        }

        private void writeUInt16(int uInt16Value) {
            // low
            buffer[position++] = (byte) (uInt16Value & 0x00ff);
            // high
            buffer[position++] = (byte) (uInt16Value >> 8 & 0x00ff);
        }
    }
}
