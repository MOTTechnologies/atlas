package com.github.manevolent.atlas.protocol.uds.request;

import com.github.manevolent.atlas.BitReader;
import com.github.manevolent.atlas.BitWriter;
import com.github.manevolent.atlas.Frame;
import com.github.manevolent.atlas.protocol.uds.UDSRequest;
import com.github.manevolent.atlas.protocol.uds.response.UDSSecurityAccessResponse;

import java.io.IOException;

public class UDSSecurityAccessRequest
        extends UDSRequest<UDSSecurityAccessResponse> implements Frame {
    private int level; // Supposed to be odd values
    private byte[] data; // Vendor-specific key

    public UDSSecurityAccessRequest() {

    }

    public UDSSecurityAccessRequest(int seed, byte[] data) {
        this.level = seed;
        this.data = data;
    }

    public UDSSecurityAccessRequest(int seed) {
        this.level = seed;
        this.data = new byte[0];
    }

    @Override
    public void read(BitReader reader) throws IOException {
        this.level = reader.readByte();

        this.data = new byte[reader.remainingBytes()];
        reader.read(data);
    }

    @Override
    public void write(BitWriter writer) throws IOException {
        writer.write(this.level);
        writer.write(this.data);
    }

    public int getLevel() {
        return level;
    }

    @Override
    public byte[] getData() {
        return data;
    }

    public byte[] getKey() {
        return getData();
    }

    @Override
    public String toString() {
        return "level=" + level + " key=" + toHexString();
    }
}
