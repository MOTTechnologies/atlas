package com.github.manevolent.atlas.protocol.uds.response;

import com.github.manevolent.atlas.BitReader;
import com.github.manevolent.atlas.BitWriter;
import com.github.manevolent.atlas.Frame;
import com.github.manevolent.atlas.protocol.uds.UDSResponse;

import java.io.IOException;

// See: https://embetronicx.com/tutorials/automotive/uds-protocol/diagnostics-and-communication-management/#Communication_Control
public class UDSCommunicationControlResponse extends UDSResponse implements Frame {
    private int communicationType;
    private byte[] data;

    public UDSCommunicationControlResponse() {

    }

    public UDSCommunicationControlResponse(int communicationType, byte[] data) {
        this.communicationType = communicationType;
        this.data = data;
    }

    public UDSCommunicationControlResponse(int communicationType) {
        this(communicationType, new byte[0]);
    }

    @Override
    public void read(BitReader reader) throws IOException {
        this.communicationType = reader.readByte() & 0xFF;
        this.data = reader.readRemaining();
    }

    @Override
    public void write(BitWriter writer) throws IOException {
        writer.write(communicationType);
        writer.write(data);
    }

    @Override
    public byte[] getData() {
        return data;
    }

    @Override
    public String toString() {
        // I could make an enum here, but I am burnt out making those.
        // Subaru likes to do 0x3 before flashing; disable RX + TX.
        return "type=" + communicationType + " data=" + toHexString();
    }
}
