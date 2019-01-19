package ch.alni.fido.uaf.protocol.v1_1.registry;

import ch.alni.fido.registry.v1_1.TransactionConfirmationDisplay;

/**
 * TODO: javadoc
 */
public class TransactionConfirmationDisplaySerializer extends SetToIntSerializer<TransactionConfirmationDisplay> {
    @Override
    int setValueToInt(TransactionConfirmationDisplay setValue) {
        return setValue.getCode();
    }
}
