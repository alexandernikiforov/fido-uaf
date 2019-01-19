package ch.alni.fido.uaf.protocol.v1_1.registry;

import ch.alni.fido.registry.v1_1.AttachmentHint;

/**
 * TODO: javadoc
 */
public class AttachmentHintSerializer extends SetToIntSerializer<AttachmentHint> {
    @Override
    int setValueToInt(AttachmentHint setValue) {
        return setValue.getCode();
    }
}
