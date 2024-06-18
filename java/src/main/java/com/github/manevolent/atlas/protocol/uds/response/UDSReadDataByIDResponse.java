package com.github.manevolent.atlas.protocol.uds.response;

import com.github.manevolent.atlas.BitReader;
import com.github.manevolent.atlas.BitWriter;
import com.github.manevolent.atlas.Frame;
import com.github.manevolent.atlas.protocol.uds.flag.DataIdentifier;
import com.github.manevolent.atlas.protocol.uds.UDSResponse;

import java.io.IOException;

public class UDSReadDataByIDResponse extends UDSResponse implements Frame {
    private int did;
    private byte[] value;

    public UDSReadDataByIDResponse() {
        this.did = 0;
        this.value = new byte[0];
    }

    public UDSReadDataByIDResponse(int did, byte[] value) {
        this.did = did;
        this.value = value;
    }

    @Override
    public void read(BitReader reader) throws IOException {
        did = reader.readShort() & 0xFFFF;
        value = new byte[reader.remaining() / 8];
        reader.read(value);
    }

    @Override
    public void write(BitWriter writer) throws IOException {
        writer.writeShort((short) (did & 0xFFFF));
        writer.write(getData());
    }

    @Override
    public byte[] getData() {
        return value;
    }

    @Override
    public String toString() {
        DataIdentifier found = DataIdentifier.findByDid((short)did);
        return String.format("%04X(%s) value=%s", (short)did, found.text(), Frame.toHexString(getData()));
    }
}
