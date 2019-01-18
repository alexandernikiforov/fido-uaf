package ch.alni.fido.uaf.protocol.v1_1;

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

    static class Serializer extends SetToIntSerializer<TransactionConfirmationDisplay> {
        @Override
        int setValueToInt(TransactionConfirmationDisplay setValue) {
            return setValue.getCode();
        }
    }

}
