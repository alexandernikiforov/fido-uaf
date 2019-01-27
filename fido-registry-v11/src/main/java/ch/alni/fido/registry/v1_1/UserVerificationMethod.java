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

public enum UserVerificationMethod {
    USER_VERIFY_PRESENCE(0x00000001),
    USER_VERIFY_FINGERPRINT(0x00000002),
    USER_VERIFY_PASSCODE(0x00000004),
    USER_VERIFY_VOICEPRINT(0x00000008),
    USER_VERIFY_FACEPRINT(0x00000010),
    USER_VERIFY_LOCATION(0x00000020),
    USER_VERIFY_EYEPRINT(0x00000040),
    USER_VERIFY_PATTERN(0x00000080),
    USER_VERIFY_HANDPRINT(0x00000100),
    USER_VERIFY_NONE(0x00000200),
    USER_VERIFY_ALL(0x00000400);

    private final long code;

    UserVerificationMethod(long code) {
        this.code = code;
    }

    public long getCode() {
        return code;
    }

}
