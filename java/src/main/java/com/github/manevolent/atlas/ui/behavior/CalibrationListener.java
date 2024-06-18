package com.github.manevolent.atlas.ui.behavior;

import com.github.manevolent.atlas.model.Calibration;

public interface CalibrationListener {

    void onCalibrationChanged(Calibration oldCalibration, Calibration newCalibration);

}
