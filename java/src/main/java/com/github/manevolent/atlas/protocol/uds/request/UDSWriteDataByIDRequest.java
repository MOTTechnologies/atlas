package com.github.manevolent.atlas.protocol.uds.request;

import com.github.manevolent.atlas.BitReader;
import com.github.manevolent.atlas.BitWriter;
import com.github.manevolent.atlas.protocol.uds.flag.DataIdentifier;
import com.github.manevolent.atlas.protocol.uds.UDSRequest;
import com.github.manevolent.atlas.protocol.uds.response.UDSWriteDataByIDResponse;

import java.io.IOException;

public class UDSWriteDataByIDRequest extends UDSRequest<UDSWriteDataByIDResponse> {
    private int did;
    private byte[] data;

    public UDSWriteDataByIDRequest(int did, byte[] data) {
        this.did = did;
        this.data = data;
    }

    public UDSWriteDataByIDRequest(DataIdentifier id, byte[] data) {
        this.did = id.collapse();
        this.data = data;
    }

    public UDSWriteDataByIDRequest() {

    }

    public int getDid() {
        return did;
    }

    public void setDid(int did) {
        this.did = did;
    }

    @Override
    public byte[] getData() {
        return data;
    }

    public void setData(byte[] data) {
        this.data = data;
    }

    @Override
    public void read(BitReader reader) throws IOException {
        this.did = (reader.readShort() & 0xFFFF);
        this.data = reader.readRemaining();
    }

    @Override
    public void write(BitWriter writer) throws IOException {
        writer.writeShort((short) (did & 0xFFFF));
        writer.write(data);
    }

    @Override
    public String toString() {
        DataIdentifier found = DataIdentifier.findByDid((short)did);
        return String.format("%04X(%s), value=%s", (short)did, found.text(), toHexString());
    }
}
