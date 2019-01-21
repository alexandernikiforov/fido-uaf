package ch.alni.fido.uaf.authnr.tlv;

import com.google.common.base.Preconditions;

import java.util.Arrays;

/**
 * Immutable byte array.
 */
public class ImmutableByteArray {

    private final byte[] data;

    private ImmutableByteArray(byte[] data) {
        this.data = new byte[data.length];
        System.arraycopy(data, 0, this.data, 0, data.length);
    }

    private ImmutableByteArray(byte[] data, int pos, int length) {
        this.data = new byte[length];
        System.arraycopy(data, pos, this.data, 0, length);
    }


    public static ImmutableByteArray of(byte[] data) {
        Preconditions.checkArgument(null != data, "data cannot be null");
        return new ImmutableByteArray(data);
    }

    public static ImmutableByteArray of(byte[] data, int pos, int length) {
        Preconditions.checkArgument(null != data, "data cannot be null");
        Preconditions.checkArgument(pos >= 0, "position must be non negative");
        Preconditions.checkArgument(length > 0, "length must be positive");
        Preconditions.checkArgument(length + pos <= data.length, "cannot read more data than given");
        return new ImmutableByteArray(data, pos, length);
    }

    public byte[] toByteArray() {
        return Arrays.copyOf(data, data.length);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        ImmutableByteArray that = (ImmutableByteArray) o;
        return Arrays.equals(data, that.data);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(data);
    }
}
