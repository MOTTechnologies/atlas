package com.github.manevolent.atlas.protocol.uds.request;

import com.github.manevolent.atlas.BitReader;
import com.github.manevolent.atlas.BitWriter;
import com.github.manevolent.atlas.protocol.uds.flag.DataIdentifier;
import com.github.manevolent.atlas.protocol.uds.UDSRequest;
import com.github.manevolent.atlas.protocol.uds.response.UDSReadDataByIDResponse;

import java.io.IOException;
import java.util.Arrays;
import java.util.stream.Collectors;

public class UDSReadDataByIDRequest extends UDSRequest<UDSReadDataByIDResponse> {
    private int[] dids;

    public UDSReadDataByIDRequest(int... dids) {
        this.dids = dids;
    }

    public UDSReadDataByIDRequest() {

    }

    public int[] getDids() {
        return dids;
    }

    public void setDids(int[] dids) {
        this.dids = dids;
    }

    @Override
    public void read(BitReader reader) throws IOException {
        int numDids = reader.remaining() / 16;
        dids = new int[numDids];
        for (int i = 0; i < numDids; i ++) {
            dids[i] = reader.readShort();
        }
    }

    @Override
    public void write(BitWriter writer) throws IOException {
        for (int did : dids) {
            writer.writeShort((short) did);
        }
    }

    @Override
    public String toString() {
        return "dids=" + Arrays.stream(dids)
                .mapToObj(did -> {
                    DataIdentifier found = DataIdentifier.findByDid((short)did);
                    return String.format("%04X(%s)", (short)did, found.text());
                })
                .collect(Collectors.joining(","));
    }
}
