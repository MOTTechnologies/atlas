package com.github.manevolent.atlas.protocol.subaru.uds.response;

import com.github.manevolent.atlas.BitReader;
import com.github.manevolent.atlas.BitWriter;
import com.github.manevolent.atlas.protocol.subaru.uds.request.SubaruStatus1Request;
import com.github.manevolent.atlas.protocol.uds.UDSResponse;

import java.io.IOException;

public class SubaruStatus1Response extends UDSResponse {
    private int code;
    private byte[] data;

    public SubaruStatus1Response() {

    }

    public SubaruStatus1Response(int code, byte[] data) {
        this.code = code;
        this.data = data;
    }

    @Override
    public void read(BitReader reader) throws IOException {
        code = reader.readByte() & 0xFF;
        data = reader.readRemaining();
    }

    @Override
    public void write(BitWriter writer) throws IOException {
        writer.write(code & 0xFF);
        writer.write(data);
    }

    @Override
    public byte[] getData() {
        return data;
    }

    @Override
    public String toString() {
        return String.format("code=0x%02X data=%s", code, toHexString());
    }

}
