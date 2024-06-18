package com.github.manevolent.atlas.model;

public enum DTCSystem {
    POWERTRAIN("P"),
    CHASSIS("C"),
    BODY("B"),
    USER_NETWORK("U");

    private final String code;

    DTCSystem(String code) {
        this.code = code;
    }

    public String getCode() {
        return code;
    }

    @Override
    public String toString() {
        return getCode();
    }
}
