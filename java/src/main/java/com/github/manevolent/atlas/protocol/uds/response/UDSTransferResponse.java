package com.github.manevolent.atlas.protocol.uds.response;

import com.github.manevolent.atlas.BitReader;
import com.github.manevolent.atlas.BitWriter;
import com.github.manevolent.atlas.protocol.uds.UDSResponse;

import java.io.IOException;

public class UDSTransferResponse extends UDSResponse {
    private int index;
    private byte[] data;

    public UDSTransferResponse() {

    }

    public UDSTransferResponse(int index, byte[] data) {
        this.index = index;
        this.data = data;
    }

    public UDSTransferResponse(int index) {
        this(index, new byte[0]);
    }

    @Override
    public void read(BitReader reader) throws IOException {
        this.index = reader.readByte() & 0xFF;
        this.data = reader.readRemaining();
    }

    @Override
    public void write(BitWriter writer) throws IOException {
        writer.write(index & 0xFF);
        writer.write(data);
    }

    public int getIndex() {
        return index;
    }

    @Override
    public byte[] getData() {
        return data;
    }

    @Override
    public String toString() {
        return "index=" + index + " data=" + toHexString();
    }
}