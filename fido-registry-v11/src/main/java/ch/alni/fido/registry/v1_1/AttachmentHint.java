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
