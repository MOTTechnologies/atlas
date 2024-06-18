package com.github.manevolent.atlas.protocol.uds.flag;

// See: https://embetronicx.com/tutorials/automotive/uds-protocol/data-transmission-in-uds-protocol/
public enum DynamicallyDefineSubFunction implements Flag {
    RESERVED(0x00),
    DEFINE_BY_IDENTIFIER(0x01),
    DEFINE_BY_ADDRESS(0x02),
    CLEAR(0x03);

    private final int code;
    DynamicallyDefineSubFunction(int code) {
        this.code = code;
    }

    @Override
    public int getCode() {
        return code;
    }
}