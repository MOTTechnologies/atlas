package com.github.manevolent.atlas.logic.subaru;

import com.github.manevolent.atlas.logic.AbstractSupportedDTC;

import com.github.manevolent.atlas.model.Calibration;
import com.github.manevolent.atlas.model.DTC;

import java.io.IOException;

public class SubaruDISupportedDTC extends AbstractSupportedDTC {
    private final SubaruDIOS os;

    private final long enabledOffset;
    private final int checkDTCNumber;
    private final int bitNumber;

    public SubaruDISupportedDTC(SubaruDIOS os, DTC dtc,
                                long enabledOffset,
                                int checkDTCNumber,
                                int bitNumber) {
        super(dtc);

        this.os = os;
        this.enabledOffset = enabledOffset;
        this.checkDTCNumber = checkDTCNumber;
        this.bitNumber = bitNumber;
    }

    public int getCheckDTCNumber() {
        return checkDTCNumber;
    }

    @Override
    public boolean isEnabled() throws IOException {
        Calibration calibration = os.getCalibration();
        int b = calibration.read(enabledOffset) & 0xFF;
        int mask = 1 << bitNumber;
        return (b & mask) == mask;
    }

    @Override
    protected void setEnabledUncontrolled(boolean enabled) throws IOException {
        Calibration calibration = os.getCalibration();
        int b = calibration.read(enabledOffset) & 0xFF;
        int mask = 1 << bitNumber;
        if (!enabled) {
            mask = ~mask & 0xFF;
            b = b & mask;
            calibration.write(enabledOffset, b & 0xFF);
        } else {
            b = b | mask;
            calibration.write(enabledOffset, b & 0xFF);
        }
    }
}
