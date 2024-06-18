package com.github.manevolent.atlas.protocol.j2534;

// See: https://www.opusivs.com/support/j2534-support/passthru-sae-j2534-dll/possible-error-codes
public enum J2534Protocol {
    J1850VPW(1),
    J1850PWM(2),
    ISO9141(3),
    ISO14230(4),
    CAN(5),
    ISO15765(6), // AKA ISO-TP
    SCI_A_ENGINE(7),
    SCI_A_TRANS(8),
    SCI_B_ENGINE(9),
    SCI_B_TRANS(10);

    private int code;
    J2534Protocol(int code) {
        this.code = code;
    }

    public int getCode() {
        return code;
    }

}
