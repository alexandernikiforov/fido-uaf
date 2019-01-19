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
