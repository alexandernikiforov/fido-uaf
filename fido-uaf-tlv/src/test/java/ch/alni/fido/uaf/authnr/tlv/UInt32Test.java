package ch.alni.fido.uaf.authnr.tlv;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class UInt32Test {

    @Test
    public void testOf() {
        final UInt32 uInt32 = UInt32.of(0x7ffafbfc);
        assertThat(uInt32.getByte0()).isEqualTo((byte) 0xfc);
        assertThat(uInt32.getByte1()).isEqualTo((byte) 0xfb);
        assertThat(uInt32.getByte2()).isEqualTo((byte) 0xfa);
        assertThat(uInt32.getByte3()).isEqualTo((byte) 0x7f);
    }
}