package com.github.manevolent.atlas.protocol.uds;

import com.github.manevolent.atlas.BitReader;

import java.io.IOException;

public class UDSUnknownBody extends UDSBody {
    private int sid;
    private byte[] data;

    @Override
    public void read(BitReader reader) throws IOException {
        this.data = reader.readRemaining();
    }

    @Override
    public byte[] getData() {
        return data;
    }

    public int getSid() {
        return sid;
    }

    public void setSid(int sid) {
        this.sid = sid;
    }

    @Override
    public String toString() {
        return "sid=0x" + Integer.toHexString(sid).toUpperCase() + " " + super.toString();
    }
}
