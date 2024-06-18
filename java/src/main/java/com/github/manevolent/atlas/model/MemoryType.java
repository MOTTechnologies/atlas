package com.github.manevolent.atlas.model;

public enum MemoryType {

    /**
     * The bootloader is a region of memory that usually isn't reprogrammable. The bootloader is typically code + data
     * that is flashed by the OEM when the ECU is manufactured and will be loaded whenever the ECU is powered on, or
     * perhaps if the ECU is commanded to enter a PROGRAMMING session via the DiagSessionControl UDS command. The
     * bootloader usually is responsible for fully reprogramming the ECU.
     */
    BOOTLOADER("Bootloader"),

    /**
     * Code flash is a region of memory that is typically reprogrammable. Multiple sections might exist, but in many
     * ECUs only one code flash section is available. For example, in the RH850's used in the 2022+ WRX, 0x00010000
     * to 0x00040000 (4MB) is the typically observed code section. This is the primary target for recalibrating.
     */
    CODE("Code Flash"),

    /**
     * EEPROM is the region of memory that is likely re-writable, but will store things like immobilizer keys and
     * "learned" values like feedback knock and learned waste-gate parameters in the VB's case. On the VB WRX,
     * EEPROM is at 0xfeef0000 and is 64KB in size. Due to its requirements around persistence, EEPROM is non-volatile.
     */
    EEPROM("EEPROM"),

    /**
     * RAM is the volatile memory section, typically much larger than EEPROM with significantly higher performance
     * capabilities. RAM is not persisted and only persists while power is delivered to the ECU. The VB WRX has various
     * RAM sections.
     */
    RAM("RAM");

    private final String name;

    MemoryType(String name) {
        this.name = name;
    }


    @Override
    public String toString() {
        return name;
    }
}
