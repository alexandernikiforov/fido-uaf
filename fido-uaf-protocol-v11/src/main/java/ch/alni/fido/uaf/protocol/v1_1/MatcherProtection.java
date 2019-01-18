package ch.alni.fido.uaf.protocol.v1_1;

public enum MatcherProtection {
    MATCHER_PROTECTION_SOFTWARE(0x0001),
    MATCHER_PROTECTION_TEE(0x0002),
    MATCHER_PROTECTION_ON_CHIP(0x0004);

    private final int code;

    MatcherProtection(int code) {
        this.code = code;
    }

    public int getCode() {
        return code;
    }

    static class Serializer extends SetToIntSerializer<MatcherProtection> {

        @Override
        int setValueToInt(MatcherProtection setValue) {
            return setValue.getCode();
        }
    }

}
