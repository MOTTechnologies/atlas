package com.github.manevolent.atlas.logic;

import com.github.manevolent.atlas.model.Axis;
import com.github.manevolent.atlas.model.Calibration;

import java.io.IOException;
import java.util.EnumSet;

import static com.github.manevolent.atlas.model.Axis.*;

public interface TablePlan {

    OS getOS();

    default Calibration getCalibration() {
        return getOS().getCalibration();
    }

    int getDimensions();

    default EnumSet<Axis> getAxes() {
        switch (getDimensions()) {
            case 1:
                return EnumSet.of(X);
            case 2:
                return EnumSet.of(X, Y);
            case 3:
                return EnumSet.of(X, Y, Z);
            default:
                throw new UnsupportedOperationException();
        }
    }

    TableStructure getStructure(TableExecution execution) throws IOException;

}
