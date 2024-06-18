package com.github.manevolent.atlas.protocol.can;

import com.github.manevolent.atlas.Address;

public class CANArbitrationId implements Address {
    public static final CANArbitrationId ZERO = id(0x0000);

    public static CANArbitrationId id(int id) {
        return new CANArbitrationId(id);
    }

    private final int arbitrationId;

    public CANArbitrationId(int arbitrationId) {
        this.arbitrationId = arbitrationId;
    }

    public int getArbitrationId() {
        return arbitrationId;
    }

    @Override
    public int hashCode() {
        return arbitrationId;
    }

    @Override
    public boolean equals(Object obj) {
        return (obj instanceof CANArbitrationId id && id.arbitrationId == this.arbitrationId);
    }

    @Override
    public String toString() {
        return Integer.toHexString(arbitrationId).toUpperCase();
    }

    @Override
    public byte[] getData() {
        byte[] arbitrationIdBytes = new byte[4];
        arbitrationIdBytes[0] = (byte) ((arbitrationId >> 24) & 0xFF);
        arbitrationIdBytes[1] = (byte) ((arbitrationId >> 16) & 0xFF);
        arbitrationIdBytes[2] = (byte) ((arbitrationId >> 8) & 0xFF);
        arbitrationIdBytes[3] = (byte) ((arbitrationId) & 0xFF);
        return arbitrationIdBytes;
    }

    @Override
    public int toInt() {
        return arbitrationId;
    }
}
