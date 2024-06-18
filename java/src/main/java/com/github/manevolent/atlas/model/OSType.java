package com.github.manevolent.atlas.model;

import com.github.manevolent.atlas.checked.CheckedFunction;
import com.github.manevolent.atlas.logic.OS;
import com.github.manevolent.atlas.logic.subaru.SubaruDIOS;

import java.io.IOException;

public enum OSType {
    SUBARU_DI_RH850(SubaruDIOS::new);

    private final CheckedFunction<Calibration, OS, IOException> constructor;

    OSType(CheckedFunction<Calibration, OS, IOException> constructor) {
        this.constructor = constructor;
    }

    public OS createOS(Calibration calibration) throws IOException {
        return constructor.applyChecked(calibration);
    }

    @Override
    public String toString() {
        return "Subaru DI (RH850)";
    }
}
