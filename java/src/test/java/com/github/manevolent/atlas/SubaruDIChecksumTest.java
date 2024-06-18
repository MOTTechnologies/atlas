package com.github.manevolent.atlas;

import com.github.manevolent.atlas.connection.subaru.Calibrations;
import com.github.manevolent.atlas.model.Calibration;
import com.github.manevolent.atlas.model.crypto.SubaruDIChecksum;
import com.github.manevolent.atlas.ssm4.Crypto;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class SubaruDIChecksumTest {

    @Test
    public void testChecksum() throws IOException {
        byte[] data = Crypto.toByteArray("5555B039BEEF0283AAFABCDEF01234567890");
        Calibration badCalibration = Calibrations.createCalibration("test", data);
        for (int i = 0; i <= 0xFFFF; i ++) {
            data[2] = (byte)((i >> 8) & 0xFF);
            data[3] = (byte)(i & 0xFF);

            SubaruDIChecksum checksum = new SubaruDIChecksum(0x4);
            assertFalse(checksum.validate(badCalibration));
            checksum.correct(badCalibration);
            assertTrue(checksum.validate(badCalibration));
        }
    }

}
