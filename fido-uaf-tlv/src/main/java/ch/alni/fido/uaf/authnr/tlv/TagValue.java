package ch.alni.fido.uaf.authnr.tlv;

/**
 * Common interface to be implemented by elements that can be part of TLV data.
 */
public interface TagValue {

    int length();

    byte[] toByteArray();
}
