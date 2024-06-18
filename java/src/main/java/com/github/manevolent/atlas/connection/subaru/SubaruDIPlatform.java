package com.github.manevolent.atlas.connection.subaru;

import com.github.manevolent.atlas.connection.Platform;

import com.github.manevolent.atlas.model.Calibration;
import com.github.manevolent.atlas.model.Checksum;
import com.github.manevolent.atlas.model.Vehicle;
import com.github.manevolent.atlas.model.crypto.MemoryEncryptionType;
import com.github.manevolent.atlas.model.crypto.SubaruDIChecksum;

import com.github.manevolent.atlas.protocol.subaru.SubaruDITComponent;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public enum SubaruDIPlatform implements Platform {
    USDM_2022_WRX_MT(
            Arrays.asList(
                    "LHBH610B00G",
                    "LHBH700B00G",
                    "LHBH710B00G",
                    "LHBH720B00G",
                    "LHBH730B00G",
                    "LHBH731B00G",
                    "LHBH740B00G",
                    "LHBH800B00G", // 09-88-22, 06/29/22
                    "LHBHB10B00G", // 09-102-23, 06/28/23
                    "LHBHD10B00H",
                    "LHBHD00B00G",
                    "LHGHA10B00G", // 09-94-22R, 01/24/23 (revised 11/27/23)
                    "LHBHC00B00G" // 09-114-23R, 11/27/23 (revised 03/18/24)
            ),
            Vehicle.builder().withMake("Subaru").withMarket("USDM").withModel("WRX").withYear("2022")
                .withTransmission("MT").build(),
            SubaruDITComponent.ENGINE_1, SubaruDITComponent.ENGINE_2,
            SubaruDITComponent.CENTRAL_GATEWAY, SubaruDITComponent.BROADCAST,
            MemoryEncryptionType.SUBARU_DIT,
            new SubaruDIChecksum(0x3EFF00), 0x00010000, 0x00400000
    ),
    USDM_2023_WRX_MT(
            Arrays.asList(
                    "LHBKC40M00G",
                    "LHBKC30M00G" // 09-114-23R, 11/27/23 (revised 03/18/24)
            ),
            Vehicle.builder().withMake("Subaru").withMarket("USDM").withModel("WRX").withYear("2023")
                    .withTransmission("MT").build(),
            SubaruDITComponent.ENGINE_1, SubaruDITComponent.ENGINE_2,
            SubaruDITComponent.CENTRAL_GATEWAY, SubaruDITComponent.BROADCAST,
            MemoryEncryptionType.SUBARU_DIT,
            new SubaruDIChecksum(0x3EFF00), 0x00010000, 0x00400000
    );

    private final MemoryEncryptionType encryptionType;

    /**
     * The result of SubaruStatus1Request func=0x00 which requested the calibration ID
     */
    private final List<String> calibrationIds;

    /**
     * The vehicle the platform represents
     */
    private final Vehicle vehicle;

    /**
     * The ECU and gateway arbitration IDs
     */
    private final SubaruDITComponent ecu_1;
    private final SubaruDITComponent ecu_2;
    private final SubaruDITComponent gateway;
    private final SubaruDITComponent broadcast;

    private final long flashStart, flashEnd;
    private final Checksum checksum;

    SubaruDIPlatform(List<String> calibrationIds, Vehicle vehicle,
                     SubaruDITComponent ecu_1, SubaruDITComponent ecu_2,
                     SubaruDITComponent gateway, SubaruDITComponent broadcast,
                     MemoryEncryptionType encryptionType,
                     Checksum checksum, long flashStart, long flashEnd) {
        this.encryptionType = encryptionType;
        this.calibrationIds = Collections.unmodifiableList(calibrationIds);
        this.vehicle = vehicle;
        this.ecu_1 = ecu_1;
        this.ecu_2 = ecu_2;
        this.gateway = gateway;
        this.broadcast = broadcast;
        this.flashStart = flashStart;
        this.flashEnd = flashEnd;
        this.checksum = checksum;
    }

    public List<String> getCalibrationIds() {
        return calibrationIds;
    }

    public SubaruDITComponent getEcu1() {
        return ecu_1;
    }

    public SubaruDITComponent getEcu2() {
        return ecu_2;
    }

    public SubaruDITComponent getBroadcast() {
        return broadcast;
    }

    public SubaruDITComponent getGateway() {
        return gateway;
    }

    public MemoryEncryptionType getEncryptionType() {
        return encryptionType;
    }

    @Override
    public Vehicle getVehicle() {
        return vehicle;
    }

    @Override
    public Checksum getChecksum(Calibration calibration) {
        return checksum;
    }

    public long getFlashStart() {
        return flashStart;
    }

    public long getFlashEnd() {
        return flashEnd;
    }

    public int getFlashSize() {
        return (int) (getFlashEnd() - getFlashStart());
    }

    public static SubaruDIPlatform find(String calibrationId) {
        return Arrays.stream(values())
                .filter(platform -> platform.getCalibrationIds().contains(calibrationId))
                .findFirst().orElse(null);
    }
}
