package com.github.manevolent.atlas.protocol.uds.request;

import com.github.manevolent.atlas.BitReader;
import com.github.manevolent.atlas.BitWriter;
import com.github.manevolent.atlas.Frame;
import com.github.manevolent.atlas.protocol.uds.UDSRequest;
import com.github.manevolent.atlas.protocol.uds.response.UDSTransferExitResponse;
import com.github.manevolent.atlas.protocol.uds.response.UDSTransferResponse;

import java.io.IOException;

public class UDSTransferExitRequest extends UDSRequest<UDSTransferExitResponse> implements Frame {
    private byte[] data;

    public UDSTransferExitRequest() {
        data = new byte[0];
    }

    @Override
    public void read(BitReader reader) throws IOException {
        data = reader.readRemaining();
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
