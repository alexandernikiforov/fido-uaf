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

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class RecursiveDescentParserTest {
    private final RecursiveDescentParser parser = new RecursiveDescentParser();
    private final RecursiveDescentSerializer serializer = new RecursiveDescentSerializer();

    @Test(expected = IllegalArgumentException.class)
    public void parseNull() {
        parser.parse(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void parseEmpty() {
        parser.parse(new byte[]{});
    }

    @Test
    public void testParseSingleTag() {
        final byte[] singleTag = new byte[]{
                0x0B, 0x2E,
                0x07, 0x00,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
        };

        final TlvStruct result = parser.parse(singleTag);
        assertThat(result.tag()).isEqualTo(0x2E0B);
        assertThat(result.length()).isEqualTo(7);
        assertThat(result.composite()).isFalse();

        assertThat(serializer.toByteArray(result)).isEqualTo(singleTag);
    }

    @Test
    public void testParseCompositeTag() {
        final byte[] compositeTag = new byte[]{
                0x0B, 0x3E,
                0x11, 0x00,
                // first tag
                0x0A, 0x2E,
                0x07, 0x00,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                // second tag
                0x0B, 0x2E,
                0x02, 0x00,
                0x01, 0x02
        };

        final TlvStruct result = parser.parse(compositeTag);
        assertThat(result.tag()).isEqualTo(0x3E0B);
        assertThat(result.length()).isEqualTo(17);
        assertThat(result.composite()).isTrue();

        assertThat(serializer.toByteArray(result)).isEqualTo(compositeTag);
    }

    @Test
    public void testParseRecursiveCompositeTag() {
        final byte[] compositeTlv = new byte[]{
                0x0B, 0x3E,
                0x1A, 0x00,
                // composite tag
                0x0C, 0x3E,
                0x11, 0x00,
                // *** first inner tag
                0x0A, 0x2E,
                0x07, 0x00,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                // *** second inner tag
                0x0B, 0x2E,
                0x02, 0x00,
                0x01, 0x02,
                // single tag
                0x0C, 0x2E,
                0x01, 0x00,
                0x01
        };

        final TlvStruct result = parser.parse(compositeTlv);

        assertThat(result.tag()).isEqualTo(0x3E0B);
        assertThat(result.length()).isEqualTo(26);
        assertThat(result.composite()).isTrue();

        assertThat(result.tags()).hasSize(2);
        assertThat(result.tags().get(0).composite()).isTrue();
        assertThat(result.tags().get(1).composite()).isFalse();

        // check if we can restore the original array
        assertThat(serializer.toByteArray(result)).isEqualTo(compositeTlv);
    }
}