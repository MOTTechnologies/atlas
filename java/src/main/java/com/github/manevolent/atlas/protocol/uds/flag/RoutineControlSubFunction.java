package com.github.manevolent.atlas.protocol.uds.flag;

public enum RoutineControlSubFunction implements Flag {
    START_ROUTINE(0x1),
    STOP_ROUTINE(0x2),
    REQUEST_ROUTINE_RESULTS(0x3);

    private final int code;

    RoutineControlSubFunction(int code) {
        this.code = code;
    }

    @Override
    public int getCode() {
        return code;
    }
}
