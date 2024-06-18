package com.github.manevolent.atlas.protocol.j2534;

// See: https://www.opusivs.com/support/j2534-support/passthru-sae-j2534-dll/possible-error-codes
public enum J2534Parameter {
    DATA_RATE(0x01), //

    LOOPBACK(0x03), //
    NODE_ADDRESS(0x04), //
    NETWORK_LINE(0x05), //
    P1_MIN(0x06), // Don't use
    P1_MAX(0x07), //
    P2_MIN(0x08), // Don't use
    P2_MAX(0x09), // Don't use
    P3_MIN(0x0A), //
    P3_MAX(0x0B), // Don't use
    P4_MIN(0x0C), //
    P4_MAX(0x0D), // Don't use

    W1(0x0E), //
    W2(0x0F), //
    W3(0x10), //
    W4(0x11), //
    W5(0x12), //
    TIDLE(0x13), //
    TINIL(0x14), //
    TWUP(0x15), //
    PARITY(0x16), //
    BIT_SAMPLE_POINT(0x17), //
    SYNC_JUMP_WIDTH(0x18), //
    W0(0x19), //
    T1_MAX(0x1A), //
    T2_MAX(0x1B), //

    T4_MAX(0x1C), //
    T5_MAX(0x1D), //
    ISO15765_BS(0x1E), //
    ISO15765_STMIN(0x1F), //
    DATA_BITS(0x20), //
    FIVE_BAUD_MOD(0x21), //
    BS_TX(0x22), //
    STMIN_TX(0x23), //
    T3_MAX(0x24), //
    ISO15765_WFT_MAX(0x25), //

    // J2534-2
    CAN_MIXED_FORMAT(0x8000), // /*-2*/
    J1962_PINS(0x8001), // /*-2*/
    SW_CAN_HS_DATA_RATE(0x8010), // /*-2*/
    SW_CAN_SPEEDCHANGE_ENABLE(0x8011), // /*-2*/
    SW_CAN_RES_SWITCH(0x8012), // /*-2*/
    ACTIVE_CHANNELS(0x8020), // Bitmask of channels being sampled
    SAMPLE_RATE(0x8021), // Samples/second or Seconds/sample
    SAMPLES_PER_READING(0x8022), // Samples to average into a single reading
    READINGS_PER_MSG(0x8023), // Number of readings for each active channel per PASSTHRU_MSG structure
    AVERAGING_METHOD(0x8024), // The way in which the samples will be averaged.
    SAMPLE_RESOLUTION(0x8025), // The number of bits of resolution for each channel in the subsystem. Read Only.
    INPUT_RANGE_LOW(0x8026), // Lower limit in millivolts of A/D input. Read Only.
    INPUT_RANGE_HIGH(0x8027); // Upper limit in millivolts of A/D input. Read Only.

    private int code;
    J2534Parameter(int code) {
        this.code = code;
    }

    public int getCode() {
        return code;
    }

}
