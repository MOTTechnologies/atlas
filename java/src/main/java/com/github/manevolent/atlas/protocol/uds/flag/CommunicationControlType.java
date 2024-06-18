package com.github.manevolent.atlas.protocol.uds.flag;

public enum CommunicationControlType implements Flag {
    NORMAL(0x00), // NCM
    NETWORK_MANAGEMENT(0x01), // NMCM
    BOTH(0x02);

    private int code;
    CommunicationControlType(int code) {
        this.code = code;
    }

    @Override
    public int getCode() {
        return code;
    }
}
