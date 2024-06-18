package com.github.manevolent.atlas.protocol.isotp;

import com.github.manevolent.atlas.Addressed;
import com.github.manevolent.atlas.Frame;
import com.github.manevolent.atlas.protocol.can.CANArbitrationId;

public class ISOTPFrame implements Frame, Addressed {
    private final CANArbitrationId arbitrationId;
    private final byte[] reassembled;

    public ISOTPFrame(CANArbitrationId arbitrationId, byte[] reassembled) {
        this.arbitrationId = arbitrationId;
        this.reassembled = reassembled;
    }

    @Override
    public byte[] getData() {
        return reassembled;
    }

    @Override
    public String toString() {
        String arbitrationIdString = arbitrationId != null ? arbitrationId.toString() : "(null)";
        return "arbitrationId=" + arbitrationIdString + " data={" + toHexString() + "}";
    }

    @Override
    public CANArbitrationId getAddress() {
        return arbitrationId;
    }
}
