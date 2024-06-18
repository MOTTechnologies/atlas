package com.github.manevolent.atlas.protocol.uds.flag;

public enum CommunicationControlSubFunction implements Flag {
    ENABLE_RX_AND_TX(0x00),
    ENABLE_RX_AND_DISABLE_TX(0x01),
    DISABLE_RX_AND_ENABLE_TX(0x02),
    DISABLE_RX_AND_TX(0x03),
    ENABLE_RX_AND_DISABLE_TX_WITH_ENHANCED_ADDRESS(0x04),
    ENABLE_RX_AND_TX_WITH_ENHANCED_ADDRESS(0x05);

    private int code;
    CommunicationControlSubFunction(int code) {
        this.code = code;
    }

    @Override
    public int getCode() {
        return code;
    }
}
