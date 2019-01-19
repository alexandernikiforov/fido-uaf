package ch.alni.fido.uaf.protocol.v1_1.registry;

import ch.alni.fido.registry.v1_1.MatcherProtection;

/**
 * TODO: javadoc
 */
public class MatcherProtectionSerializer extends SetToIntSerializer<MatcherProtection> {

    @Override
    int setValueToInt(MatcherProtection setValue) {
        return setValue.getCode();
    }
}
