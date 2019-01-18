package ch.alni.fido.uaf.protocol.v1_1;

public enum KeyProtection {
    KEY_PROTECTION_SOFTWARE(0x0001),
    KEY_PROTECTION_HARDWARE(0x0002),
    KEY_PROTECTION_TEE(0x0004),
    KEY_PROTECTION_SECURE_ELEMENT(0x0008),
    KEY_PROTECTION_REMOTE_HANDLE(0x0010);

    private final int code;

    KeyProtection(int code) {
        this.code = code;
    }

    public int getCode() {
        return code;
    }

    static class Serializer extends SetToIntSerializer<KeyProtection> {

        @Override
        int setValueToInt(KeyProtection setValue) {
            return setValue.getCode();
        }
    }

}
