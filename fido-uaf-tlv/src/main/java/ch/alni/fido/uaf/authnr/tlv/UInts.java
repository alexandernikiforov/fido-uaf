package ch.alni.fido.uaf.authnr.tlv;

public final class UInts {

    private UInts() {
    }

    public static boolean isUInt16(int value) {
        return value >= 0 && value <= UInt16.MAX_UINT16;
    }

    public static boolean isUInt8(int value) {
        return value >= 0 && value <= UInt8.MAX_UINT8;
    }

}
