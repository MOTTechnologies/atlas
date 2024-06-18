package com.github.manevolent.atlas.model;

import java.io.IOException;

public interface Checksum {

    /**
     * Validates a given calibration against the checksum algorithm.
     * @param calibration calibration to validate.
     * @return true if the checksum is correct, false otherwise.
     */
    boolean validate(Calibration calibration) throws IOException;

    /**
     * Corrects the checksum in a provided calibration by modifying the calibration data.
     * @param calibration calibration to correct.
     */
    void correct(Calibration calibration) throws IOException;

}
