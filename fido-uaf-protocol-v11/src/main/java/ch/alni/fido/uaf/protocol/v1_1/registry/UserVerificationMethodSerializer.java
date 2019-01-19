package ch.alni.fido.uaf.protocol.v1_1.registry;

import ch.alni.fido.registry.v1_1.UserVerificationMethod;

/**
 * TODO: javadoc
 */
public class UserVerificationMethodSerializer extends SetToLongSerializer<UserVerificationMethod> {
    @Override
    long setValueToLong(UserVerificationMethod setValue) {
        return setValue.getCode();
    }
}
