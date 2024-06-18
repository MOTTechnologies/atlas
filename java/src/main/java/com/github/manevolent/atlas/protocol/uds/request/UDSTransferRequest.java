package com.github.manevolent.atlas.protocol.uds.request;

import com.github.manevolent.atlas.BitReader;
import com.github.manevolent.atlas.BitWriter;
import com.github.manevolent.atlas.Frame;
import com.github.manevolent.atlas.protocol.uds.UDSRequest;
import com.github.manevolent.atlas.protocol.uds.response.UDSTransferResponse;

import java.io.IOException;

public class UDSTransferRequest extends UDSRequest<UDSTransferResponse> implements Frame {
    private int index;
    private long address;
    private byte[] data;

    public UDSTransferRequest() {

    }

    public UDSTransferRequest(int index, long address, byte[] data) {
        this.index = index;
        this.address = address;
        this.data = data;
    }

    @Override
    public void read(BitReader reader) throws IOException {
        this.index = reader.readByte() & 0xFF;
        this.address = (reader.readInt() & 0xFFFFFFFFL);
        this.data = reader.readRemaining();
    }

    @Override
    public void write(BitWriter writer) throws IOException {
        writer.write(index & 0xFF);
        writer.writeInt((int) (address & 0xFFFFFFFFL));
        writer.write(data);
    }

    public int getIndex() {
        return index;
    }

    public long getAddress() {
        return address;
    }

    @Override
    public byte[] getData() {
        return data;
    }

    @Override
    public String toString() {
        return "index=" + index + " addr=" + address + " data=" + toHexString();
    }
}
