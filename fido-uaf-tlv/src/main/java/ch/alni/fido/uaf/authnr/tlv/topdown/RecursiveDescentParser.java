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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import ch.alni.fido.uaf.authnr.tlv.CompositeTag;
import ch.alni.fido.uaf.authnr.tlv.SingleTag;
import ch.alni.fido.uaf.authnr.tlv.TlvParser;
import ch.alni.fido.uaf.authnr.tlv.TlvParserException;
import ch.alni.fido.uaf.authnr.tlv.TlvStruct;
import ch.alni.fido.uaf.authnr.tlv.UInt16;

/**
 * This implementation uses recursive descent to parse TLV structures.
 */
public class RecursiveDescentParser implements TlvParser {

    @Override
    public TlvStruct parse(byte[] tlvBinaryStruct) {
        if (tlvBinaryStruct == null || tlvBinaryStruct.length == 0) {
            throw new IllegalArgumentException("cannot parse null or empty TLV structure");
        }

        byte[] tlvBinaryStructCopy = Arrays.copyOf(tlvBinaryStruct, tlvBinaryStruct.length);
        return new Parser(tlvBinaryStructCopy).parseTlvStruct();
    }

    private static class Parser {
        private final byte[] tlvBinaryStruct;

        // we begin with nothing
        private int position = 0;

        private Parser(byte[] tlvBinaryStruct) {
            this.tlvBinaryStruct = tlvBinaryStruct;
        }

        private TlvStruct parseTlvStruct() {
            final int tagPosition = position;

            final UInt16 tag = readUInt16();
            final UInt16 length = readUInt16();

            if (isComposite(tag)) {
                return parseCompositeTagData(tagPosition, tag, length);
            }
            else {
                return parseSingleTagData(tagPosition, tag, length);
            }
        }

        private SingleTag parseSingleTagData(int tagPosition, UInt16 tag, UInt16 length) {
            final byte[] data = readData(length.getValue());
            return new SingleTag(tagPosition, tag, length, data);
        }

        private CompositeTag parseCompositeTagData(int tagPosition, UInt16 tag, UInt16 length) {
            final List<TlvStruct> tlvStructList = new ArrayList<>();
            final int dataPosition = position;

            do {
                final int nextTagPosition = position;
                final UInt16 nextTag = readUInt16();
                final UInt16 nextLength = readUInt16();

                final int endOfTagPosition = position + nextLength.getValue();

                if (endOfTagPosition > dataPosition + length.getValue()) {
                    throw new TlvParserException(dataPosition, "inconsistent length of tag");
                }

                if (isComposite(nextTag)) {
                    final CompositeTag compositeTag = parseCompositeTagData(nextTagPosition, nextTag, nextLength);
                    tlvStructList.add(compositeTag);
                }
                else {
                    final SingleTag singleTag = parseSingleTagData(nextTagPosition, nextTag, nextLength);
                    tlvStructList.add(singleTag);
                }

            } while (position < dataPosition + length.getValue());

            return new CompositeTag(tagPosition, tag, length, tlvStructList);
        }

        private boolean isComposite(UInt16 tag) {
            return (tag.getValue() & 0x1000) > 0;
        }

        private byte[] readData(int length) {
            if (position + length > tlvBinaryStruct.length) {
                throw new TlvParserException(position,
                        "unexpected end of data to read more data of length " + length + " at position " + position
                );
            }

            final byte[] result = Arrays.copyOfRange(tlvBinaryStruct, position, position + length);
            position += length;
            return result;
        }

        private UInt16 readUInt16() {
            if (position + 2 > tlvBinaryStruct.length) {
                throw new TlvParserException(position, "unexpected end of data to read an UIN1T6 value at position " + position);
            }

            final byte low = tlvBinaryStruct[position++];
            final byte high = tlvBinaryStruct[position++];

            return UInt16.of(low, high);
        }
    }
}
