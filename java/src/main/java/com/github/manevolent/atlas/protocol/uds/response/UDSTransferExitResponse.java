package com.github.manevolent.atlas.protocol.uds.response;

import com.github.manevolent.atlas.BitReader;
import com.github.manevolent.atlas.BitWriter;
import com.github.manevolent.atlas.protocol.uds.UDSResponse;

import java.io.IOException;

public class UDSTransferExitResponse extends UDSResponse {
    // Typically a CRC if present
    private byte[] data;

    public UDSTransferExitResponse(byte[] data) {
        this.data = data;
    }

    public UDSTransferExitResponse() {
        this(new byte[0]);
    }

    @Override
    public void read(BitReader reader) throws IOException {
        this.data = reader.readRemaining();
    }

    @Override
    public void write(BitWriter writer) throws IOException {
        writer.write(data);
    }

    @Override
    public byte[] getData() {
        return data;
    }
}