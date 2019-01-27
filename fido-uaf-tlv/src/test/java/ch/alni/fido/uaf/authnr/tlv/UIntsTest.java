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

public class UIntsTest {

    @Test
    public void testIsUInt16() {
        assertThat(UInts.isUInt16(0)).isTrue();
        assertThat(UInts.isUInt16(65535)).isTrue();

        assertThat(UInts.isUInt16(65536)).isFalse();
        assertThat(UInts.isUInt16(-65535)).isFalse();
    }

    @Test
    public void testIsUInt8() {
        assertThat(UInts.isUInt8(0)).isTrue();
        assertThat(UInts.isUInt8(255)).isTrue();
        assertThat(UInts.isUInt8(256)).isFalse();
        assertThat(UInts.isUInt8(-255)).isFalse();
    }

}