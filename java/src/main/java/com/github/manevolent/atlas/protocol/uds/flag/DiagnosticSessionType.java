package com.github.manevolent.atlas.protocol.uds.flag;

public enum DiagnosticSessionType implements Flag {
    DEFAULT_SESSION(0x01),
    PROGRAMMING_SESSION(0x02),
    EXTENDED_SESSION(0x03);

    private int code;
    DiagnosticSessionType(int code) {
        this.code = code;
    }

    @Override
    public int getCode() {
        return code;
    }
}