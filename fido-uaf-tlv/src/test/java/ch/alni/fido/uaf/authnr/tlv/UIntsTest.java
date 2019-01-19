package ch.alni.fido.uaf.authnr.tlv;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class UIntsTest {

    @Test
    public void testIsUInt16() {
        assertThat(UInts.isUInt16(0)).isTrue();
        assertThat(UInts.isUInt16(65535)).isTrue();

        assertThat(UInts.isUInt16(65536)).isFalse();
        assertThat(UInts.isUInt16(-65535)).isFalse();
    }

    @Test
    public void testIsUInt8() {
        assertThat(UInts.isUInt8(0)).isTrue();
        assertThat(UInts.isUInt8(255)).isTrue();
        assertThat(UInts.isUInt8(256)).isFalse();
        assertThat(UInts.isUInt8(-255)).isFalse();
    }

}