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

package ch.alni.fido.registry.v1_1;

public enum AttachmentHint {
    ATTACHMENT_HINT_INTERNAL(0x0001),
    ATTACHMENT_HINT_EXTERNAL(0x0002),
    ATTACHMENT_HINT_WIRED(0x0004),
    ATTACHMENT_HINT_WIRELESS(0x0008),
    ATTACHMENT_HINT_NFC(0x0010),
    ATTACHMENT_HINT_BLUETOOTH(0x0020),
    ATTACHMENT_HINT_NETWORK(0x0040),
    ATTACHMENT_HINT_READY(0x0080),
    ATTACHMENT_HINT_WIFI_DIRECT(0x0100);

    private final int code;

    AttachmentHint(int code) {
        this.code = code;
    }

    public int getCode() {
        return code;
    }

}
