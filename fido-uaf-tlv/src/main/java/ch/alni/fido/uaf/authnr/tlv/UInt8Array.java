package ch.alni.fido.uaf.authnr.tlv;

import com.google.common.base.Preconditions;

import java.util.Arrays;

/**
 * Immutable wrapper around UINT8[] tag data.
 */
public final class UInt8Array implements TagValue {

    private final byte[] data;

    private UInt8Array(byte[] data) {
        this.data = new byte[data.length];
        System.arraycopy(data, 0, this.data, 0, data.length);
    }

    public static UInt8Array of(byte[] data) {
        Preconditions.checkArgument(null != data, "data cannot be null");
        return new UInt8Array(data);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        UInt8Array that = (UInt8Array) o;
        return Arrays.equals(data, that.data);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(data);
    }

    @Override
    public int length() {
        return data.length;
    }

    @Override
    public byte[] toByteArray() {
        return Arrays.copyOf(data, data.length);
    }

}
