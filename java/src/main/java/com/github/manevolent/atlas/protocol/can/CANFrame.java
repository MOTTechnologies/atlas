package com.github.manevolent.atlas.protocol.can;

import com.github.manevolent.atlas.Address;
import com.github.manevolent.atlas.Addressed;
import com.github.manevolent.atlas.Frame;

public class CANFrame implements Frame, Addressed {
    private byte[] data;
    private Integer arbitrationId;

    public CANFrame() {

    }

    public CANFrame(int arbitrationId, byte[] data) {
        this.arbitrationId = arbitrationId;
        this.data = data;
    }

    public int getArbitrationId() {
        return arbitrationId;
    }

    public void setArbitrationId(int arbitrationId) {
        this.arbitrationId = arbitrationId;
    }

    @Override
    public byte[] getData() {
        return data;
    }

    public void setData(byte[] data) {
        this.data = data;
    }

    @Override
    public Address getAddress() {
        return new CANArbitrationId(arbitrationId);
    }

    @Override
    public String toString() {
        String arbitrationIdString = arbitrationId != null ? Integer.toHexString(arbitrationId) : "(null)";
        return "arbitrationId=" + arbitrationIdString + " data={" + toHexString() + "}";
    }
}
