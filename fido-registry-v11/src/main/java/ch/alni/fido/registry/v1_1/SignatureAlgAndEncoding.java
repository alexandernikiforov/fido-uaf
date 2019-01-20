package ch.alni.fido.registry.v1_1;

import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public enum SignatureAlgAndEncoding {

    ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW(0x0001, "SHA256withECDSA"),
    ALG_SIGN_SECP256R1_ECDSA_SHA256_DER(0x0002, "SHA256withECDSA"),
    ALG_SIGN_RSASSA_PSS_SHA256_RAW(0x0003, "SHA256withRSAandMGF1"),
    ALG_SIGN_RSASSA_PSS_SHA256_DER(0x0004, "SHA256withRSAandMGF1"),
    ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW(0x0005, "SHA256withECDSA"),
    ALG_SIGN_SECP256K1_ECDSA_SHA256_DER(0x0006, "SHA256withECDSA"),
    ALG_SIGN_SM2_SM3_RAW(0x0007, "SM3withSM2"),
    ALG_SIGN_RSA_EMSA_PKCS1_SHA256_RAW(0x0008, "SHA256withRSA"),
    ALG_SIGN_RSA_EMSA_PKCS1_SHA256_DER(0x0009, "SHA256withRSA");

    private final static Map<Integer, SignatureAlgAndEncoding> VALUE_MAP =
            Stream.of(values()).collect(Collectors.toMap(
                    SignatureAlgAndEncoding::getCode,
                    Function.identity()
            ));
    private final int code;
    private final String algorithm;

    SignatureAlgAndEncoding(int code, String algorithm) {
        this.code = code;
        this.algorithm = algorithm;
    }

    public static SignatureAlgAndEncoding fromCode(int code) {
        return Optional.ofNullable(VALUE_MAP.get(code))
                .orElseThrow(() -> new IllegalArgumentException("invalid value " + code));
    }

    public int getCode() {
        return code;
    }

    public String getAlgorithm() {
        return algorithm;
    }
}
