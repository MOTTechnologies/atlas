package com.github.manevolent.atlas.connection;

import com.github.manevolent.atlas.model.Calibration;
import com.github.manevolent.atlas.model.Checksum;
import com.github.manevolent.atlas.model.Vehicle;
import com.github.manevolent.atlas.protocol.can.CANArbitrationId;

public interface Platform {

    Vehicle getVehicle();

    Checksum getChecksum(Calibration calibration);

}
