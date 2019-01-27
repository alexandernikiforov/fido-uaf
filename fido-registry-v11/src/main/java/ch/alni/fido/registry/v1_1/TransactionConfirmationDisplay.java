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

public enum TransactionConfirmationDisplay {
    TRANSACTION_CONFIRMATION_DISPLAY_ANY(0x0001),
    TRANSACTION_CONFIRMATION_DISPLAY_PRIVILEGED_SOFTWARE(0x0002),
    TRANSACTION_CONFIRMATION_DISPLAY_TEE(0x0004),
    TRANSACTION_CONFIRMATION_DISPLAY_HARDWARE(0x0008),
    TRANSACTION_CONFIRMATION_DISPLAY_REMOTE(0x0010);

    private final int code;

    TransactionConfirmationDisplay(int code) {
        this.code = code;
    }

    public int getCode() {
        return code;
    }

}
