package ch.alni.fido.uaf.protocol.v1_1.registry;

import ch.alni.fido.registry.v1_1.KeyProtection;

/**
 * TODO: javadoc
 */
public class KeyProtectionSerializer extends SetToIntSerializer<KeyProtection> {

    @Override
    int setValueToInt(KeyProtection setValue) {
        return setValue.getCode();
    }
}
