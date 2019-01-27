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

public class UInt32Test {

    @Test
    public void testOf() {
        final UInt32 uInt32 = UInt32.of(0x7ffafbfc);
        assertThat(uInt32.getByte0()).isEqualTo((byte) 0xfc);
        assertThat(uInt32.getByte1()).isEqualTo((byte) 0xfb);
        assertThat(uInt32.getByte2()).isEqualTo((byte) 0xfa);
        assertThat(uInt32.getByte3()).isEqualTo((byte) 0x7f);
    }
}