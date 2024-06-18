package com.github.manevolent.atlas.protocol.uds.flag;

public abstract class AbstractFlag implements Flag {
    private final int code;

    protected AbstractFlag(int code) {
        this.code = code;
    }

    @Override
    public int getCode() {
        return code;
    }
}
