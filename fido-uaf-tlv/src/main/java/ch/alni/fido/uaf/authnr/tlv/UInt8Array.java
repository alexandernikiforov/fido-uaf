package ch.alni.fido.uaf.authnr.tlv;

import com.google.common.base.Preconditions;

import java.util.Arrays;

/**
 * Immutable wrapper around byte array data.
 */
public final class UInt8Array implements TagValue {

    private final byte[] data;

    private UInt8Array(byte[] data) {
        this.data = new byte[data.length];
        System.arraycopy(data, 0, this.data, 0, data.length);
    }

    private UInt8Array(byte[] data, int pos, int length) {
        this.data = new byte[length];
        System.arraycopy(data, pos, this.data, 0, length);
    }

    public static UInt8Array of(byte[] data) {
        Preconditions.checkArgument(null != data, "data cannot be null");
        return new UInt8Array(data);
    }

    public static UInt8Array of(byte[] data, int pos, int length) {
        Preconditions.checkArgument(null != data, "data cannot be null");
        Preconditions.checkArgument(pos >= 0, "position must be non negative");
        Preconditions.checkArgument(length > 0, "length must be positive");
        Preconditions.checkArgument(length + pos <= data.length, "cannot read more data than given");
        return new UInt8Array(data, pos, length);
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
