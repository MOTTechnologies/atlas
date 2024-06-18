package com.github.manevolent.atlas.connection.subaru;

import com.github.manevolent.atlas.model.Calibration;
import com.github.manevolent.atlas.model.MemoryByteOrder;
import com.github.manevolent.atlas.model.MemorySection;
import com.github.manevolent.atlas.model.MemoryType;
import com.github.manevolent.atlas.model.crypto.MemoryEncryptionType;

public final class Calibrations {

    public static Calibration createCalibration(String name, byte[] data) {
        return createCalibration(name, data, MemoryEncryptionType.NONE);
    }


    public static Calibration createCalibration(String name, byte[] data,
                                                MemoryEncryptionType encryptionType) {
        return createCalibration(name, data, 0x00000000, encryptionType);
    }

    public static Calibration createCalibration(String name, byte[] data, long baseAddress,
                                                MemoryEncryptionType encryptionType) {
        Calibration calibration = new Calibration(name);
        calibration.setReadonly(false);
        calibration.setSection(MemorySection.builder()
                .withBaseAddress(baseAddress)
                .withLength(data.length)
                .withType(MemoryType.CODE)
                .withEncryptionType(encryptionType)
                .withByteOrder(MemoryByteOrder.LITTLE_ENDIAN)
                .build());
        calibration.updateSource(data);
        return calibration;
    }

}
