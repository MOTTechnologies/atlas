package com.github.manevolent.atlas.logic;

import com.github.manevolent.atlas.model.Calibration;
import com.github.manevolent.atlas.model.DataFormat;
import com.github.manevolent.atlas.model.Table;

public abstract class AbstractTableStructure implements TableStructure {
    private final Calibration calibration;

    protected AbstractTableStructure(Calibration calibration) {
        this.calibration = calibration;
    }

    public Calibration getCalibration() {
        return calibration;
    }
}
