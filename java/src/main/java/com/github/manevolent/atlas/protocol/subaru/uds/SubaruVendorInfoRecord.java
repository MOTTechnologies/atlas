package com.github.manevolent.atlas.protocol.subaru.uds;

import java.util.Arrays;

/**
 * Corresponds to SID 0x9 for subaru vendor-related information.
 * These sub-functions give you stuff like VIN, CID, various engine state values, and so on.
 */
public enum SubaruVendorInfoRecord {
    UNKNOWN_0(0x00, 4), // Unsure what this is
    VIN(0x02, 0x12), // Your VIN
    CALIBRATION(0x04, 0x11), // This is the calibration name you see on TSBs, etc.
    UNKNOWN_6(0x06, 5),
    UNKNOWN_8(0x08, 57), // This is interesting, it includes the ignition (key cycle) counter at [3..4]
    MODULE_NAME(10, 21), // This is a string that declares which control module is replying (i.e. ECM-EngineControl)
    EMISSIONS_ID(0x13, 18); // This is the emissions testing group identifier, used by CARB/EPA/etc.
    // More exist but seem less useful to Atlas

    private final int code;
    private final int length;

    SubaruVendorInfoRecord(int code, int length) {
        this.code = code;
        this.length = length;
    }

    public int getCode() {
        return code;
    }

    public int getLength() {
        return length;
    }

    public static SubaruVendorInfoRecord find(int code) {
        return Arrays.stream(values()).filter(record -> record.getCode() == code)
                .findFirst()
                .orElse(null);
    }
}
