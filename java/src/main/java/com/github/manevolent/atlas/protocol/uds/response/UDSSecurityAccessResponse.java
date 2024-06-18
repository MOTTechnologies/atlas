package com.github.manevolent.atlas.protocol.uds.response;

import com.github.manevolent.atlas.BitReader;
import com.github.manevolent.atlas.BitWriter;
import com.github.manevolent.atlas.Frame;
import com.github.manevolent.atlas.protocol.uds.UDSResponse;

import java.io.IOException;

public class UDSSecurityAccessResponse extends UDSResponse implements Frame {
    private int level; // Supposed to be odd values
    private byte[] data; // Vendor-specific key

    public UDSSecurityAccessResponse() {

    }

    public UDSSecurityAccessResponse(int level, byte[] data) {
        this.level = level;
        this.data = data;
    }

    public UDSSecurityAccessResponse(int level) {
        this(level, new byte[0]);
    }

    @Override
    public void read(BitReader reader) throws IOException {
        this.level = reader.readByte();

        this.data = new byte[reader.remainingBytes()];
        reader.read(data);
    }

    @Override
    public void write(BitWriter writer) throws IOException {
        writer.write(level & 0xFF);
        writer.write(data);
    }

    public int getLevel() {
        return level;
    }

    @Override
    public byte[] getData() {
        return data;
    }

    public byte[] getSeed() {
        return getData();
    }

    @Override
    public String toString() {
        return "level=" + level + " seed=" + toHexString();
    }

}
