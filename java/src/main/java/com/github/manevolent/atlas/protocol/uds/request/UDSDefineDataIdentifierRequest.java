package com.github.manevolent.atlas.protocol.uds.request;

import com.github.manevolent.atlas.BitReader;
import com.github.manevolent.atlas.BitWriter;
import com.github.manevolent.atlas.protocol.uds.UDSRequest;
import com.github.manevolent.atlas.protocol.uds.flag.DynamicallyDefineSubFunction;
import com.github.manevolent.atlas.protocol.uds.response.UDSDefineDataIdentifierResponse;

import java.io.IOException;

public class UDSDefineDataIdentifierRequest extends UDSRequest<UDSDefineDataIdentifierResponse> {
    private int function;
    private int did;
    private byte[] data;

    public UDSDefineDataIdentifierRequest() {

    }

    public UDSDefineDataIdentifierRequest(DynamicallyDefineSubFunction function, int did) {
        this(function.getCode(), did);
    }

    public UDSDefineDataIdentifierRequest(int function, int did) {
        this.function = function;
        this.did = did;
        this.data = new byte[0];
    }

    public UDSDefineDataIdentifierRequest(DynamicallyDefineSubFunction function, int did, byte[] data) {
        this(function.getCode(), did, data);
    }

    public UDSDefineDataIdentifierRequest(int function, int did, byte[] data) {
        this.function = function;
        this.did = did;
        this.data = data;
    }

    public int getFunction() {
        return function;
    }

    public int getDid() {
        return did;
    }

    @Override
    public byte[] getData() {
        return data;
    }

    @Override
    public void read(BitReader reader) throws IOException {
        function = reader.readUByte();
        did = reader.readUShort();
        data = reader.readRemaining();
    }

    @Override
    public void write(BitWriter writer) throws IOException {
        writer.write(function & 0xFF);
        writer.writeShort((short) (did & 0xFFFF));

        if (data != null) {
            writer.write(data);
        }
    }

    @Override
    public String toString() {
        return "func=" + function + " did=" + Integer.toHexString(did) + " data=" + toHexString();
    }

}
