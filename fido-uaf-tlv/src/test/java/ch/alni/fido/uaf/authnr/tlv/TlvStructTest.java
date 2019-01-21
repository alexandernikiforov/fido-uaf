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

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class TlvStructTest {
    private final RecursiveDescentSerializer serializer = new RecursiveDescentSerializer();
    private final RecursiveDescentParser parser = new RecursiveDescentParser();

    @Test
    public void testCreateSingleTag() {
        final TlvStruct singleTag = TlvStruct.of(0x2e0b, UInt8Array.of(new byte[]{0x01, 0x02}));

        final byte[] tlvStruct = serializer.toByteArray(singleTag);
        assertThat(tlvStruct).isEqualTo(new byte[]{0x0b, 0x2e, 0x02, 0x00, 0x01, 0x02,});
    }

    @Test
    public void testCreateCompositeTag() {
        final TlvStruct compositeTag = TlvStruct.of(0x3e0b,
                TlvStruct.of(0x2e0b, UInt8Array.of(new byte[]{0x01, 0x02}))
        );

        final byte[] tlvStruct = serializer.toByteArray(compositeTag);
        assertThat(tlvStruct).isEqualTo(new byte[]{
                0x0b, 0x3e,
                0x06, 0x00,

                0x0b, 0x2e,
                0x02, 0x00,
                0x01, 0x02
        });
    }

    @Test
    public void testComposite() {
        final TlvStruct tlvStruct = TlvStruct.of(0x3e0b,
                TlvStruct.of(0x3e01,
                        TlvStruct.of(0x2e0b, UInt8Array.of(new byte[]{0x01, 0x02})),
                        TlvStruct.of(0x2e0b, UInt8Array.of(new byte[]{0x01, 0x02}))
                ),
                TlvStruct.of(0x2e0b, UInt8Array.of(new byte[]{0x01, 0x02})),
                TlvStruct.of(0x2e0b, UInt8Array.of(new byte[]{0x01, 0x02}))
        );

        assertThat(tlvStruct.length()).isEqualTo(28);
        assertThat(tlvStruct.tags()).hasSize(3);
        parser.parse(serializer.toByteArray(tlvStruct));
    }

}