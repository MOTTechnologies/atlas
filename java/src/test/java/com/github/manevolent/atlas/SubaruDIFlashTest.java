package com.github.manevolent.atlas;

import com.github.manevolent.atlas.connection.*;

import com.github.manevolent.atlas.connection.subaru.Calibrations;
import com.github.manevolent.atlas.connection.subaru.SubaruDIConnection;
import com.github.manevolent.atlas.connection.subaru.SubaruDIPlatform;
import com.github.manevolent.atlas.model.Calibration;
import com.github.manevolent.atlas.model.KeyProperty;
import com.github.manevolent.atlas.model.KeySet;
import com.github.manevolent.atlas.model.Project;
import com.github.manevolent.atlas.model.crypto.MemoryEncryptionType;
import com.github.manevolent.atlas.model.crypto.SubaruDIMemoryEncryption;
import com.github.manevolent.atlas.model.uds.SecurityAccessProperty;
import com.github.manevolent.atlas.connection.subaru.SubaruDIVirtualECU;

import com.github.manevolent.atlas.protocol.uds.UDSSession;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class SubaruDIFlashTest {

    @Test
    public void testWriteCalibration_Renesas() throws Exception {
        SubaruDIPlatform platform = SubaruDIPlatform.USDM_2022_WRX_MT;

        byte[] testData = new byte[platform.getFlashSize()];

        new Random(0x123412341234123L).nextBytes(testData);

        Calibration calibration = Calibrations.createCalibration(
               "LHBHB10B00G",
                testData,
                platform.getFlashStart(), MemoryEncryptionType.SUBARU_DIT);

        SubaruDIVirtualECU ecu = new SubaruDIVirtualECU(platform);

        KeySet keySet = new KeySet();
        calibration.setKeySet(keySet);
        keySet.setActive(true);
        keySet.addProperty(SubaruDIConnection.flashWriteKeyProperty,
                new SecurityAccessProperty(1, ecu.getEngineKey1()));
        keySet.addProperty(SubaruDIConnection.gatewayKeyProperty,
                new SecurityAccessProperty(7, ecu.getGatewayKey()));
        keySet.addProperty(SubaruDIMemoryEncryption.keyProperty,
                new KeyProperty(ecu.getFeistelKey()));

        Project project = Project.builder().build();

        calibration.getSection().setEncryptionType(MemoryEncryptionType.SUBARU_DIT);
        calibration.getSection().setup(project);

        // Set required magic header
        calibration.write(new byte[] { 0x55, 0x55 }, calibration.getBaseAddress(), 0, 2);

        platform.getChecksum(calibration).correct(calibration);


        ecu.setProject(project);
        ecu.setCalibration(calibration);
        project.setKeySets(Collections.singletonList(keySet));

        SubaruDIConnection connection = new SubaruDIConnection(ecu::getDeviceProvider);

        Thread thread = ecu.start();
        try (UDSSession session = connection.connect(SessionType.NORMAL)) {
            platform = (SubaruDIPlatform) connection.identify();
            connection.setProject(project);
            FlashResult result = connection.writeCalibration(platform, calibration, (a, b) -> { /* Ignored */ });
            assertEquals(FlashResult.State.SUCCESS, result.getState());
            assertEquals(testData.length, result.getBytesWritten());
        } finally {
            thread.interrupt();
        }
    }

}
