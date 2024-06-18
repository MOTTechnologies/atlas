package com.github.manevolent.atlas.protocol.uds.flag;

public enum DTCControlMode implements Flag {
    DTC_ON(0x01),
    DTC_OFF(0x02);

    private final int code;
    DTCControlMode(int code) {
        this.code = code;
    }

    @Override
    public int getCode() {
        return code;
    }
}
