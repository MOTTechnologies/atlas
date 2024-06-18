package com.github.manevolent.atlas.protocol.uds.request;

import com.github.manevolent.atlas.BitReader;
import com.github.manevolent.atlas.BitWriter;
import com.github.manevolent.atlas.Frame;
import com.github.manevolent.atlas.protocol.uds.UDSRequest;
import com.github.manevolent.atlas.protocol.uds.flag.CommunicationControlSubFunction;
import com.github.manevolent.atlas.protocol.uds.flag.CommunicationControlType;
import com.github.manevolent.atlas.protocol.uds.flag.Flag;
import com.github.manevolent.atlas.protocol.uds.response.UDSCommunicationControlResponse;

import java.io.IOException;

// See: https://embetronicx.com/tutorials/automotive/uds-protocol/diagnostics-and-communication-management/#Communication_Control
public class UDSCommunicationControlRequest extends UDSRequest<UDSCommunicationControlResponse> implements Frame {
    private int subFunction;
    private int communicationType;
    private int nodeId;

    public UDSCommunicationControlRequest() {

    }

    public UDSCommunicationControlRequest(int subFunction, int communicationType, int nodeId) {
        this.subFunction = subFunction;
        this.communicationType = communicationType;
        this.nodeId = nodeId;
    }

    public UDSCommunicationControlRequest(int subFunction, int communicationType) {
        this(subFunction, communicationType, -1);
    }

    public UDSCommunicationControlRequest(CommunicationControlSubFunction subFunction,
                                          CommunicationControlType communicationType) {
        this(subFunction.getCode(), communicationType.getCode(), -1);
    }

    @Override
    public void read(BitReader reader) throws IOException {
        this.subFunction = reader.readByte() & 0xFF;
        this.communicationType = reader.readByte() & 0xFF;

        if (reader.available() > 0) {
            this.nodeId = reader.readShort() & 0xFFFF;
        }
    }

    @Override
    public void write(BitWriter writer) throws IOException {
        writer.write(this.subFunction);
        writer.write(this.communicationType);

        if (this.nodeId >= 0) {
            writer.writeShort((short) (nodeId & 0xFFFF));
        }
    }

    public int getSubFunction() {
        return subFunction;
    }

    public int getCommunicationType() {
        return communicationType;
    }

    public int getNodeId() {
        return nodeId;
    }

    @Override
    public String toString() {
        return "subfunc=" +
                Flag.find(CommunicationControlSubFunction.class, subFunction)
                        .map(CommunicationControlSubFunction::name)
                        .orElse(Integer.toString(subFunction))
                + " type=" +
                Flag.find(CommunicationControlType.class, communicationType)
                        .map(CommunicationControlType::name)
                        .orElse(Integer.toString(communicationType))
                + (nodeId >= 0 ? " nodeId=0x" + Integer.toHexString(nodeId) : "");
    }
}
