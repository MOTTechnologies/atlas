package com.github.manevolent.atlas.protocol.uds.response;

import com.github.manevolent.atlas.BitReader;
import com.github.manevolent.atlas.BitWriter;
import com.github.manevolent.atlas.protocol.uds.flag.NegativeResponseCode;
import com.github.manevolent.atlas.protocol.uds.UDSResponse;

import java.io.IOException;
import java.util.Arrays;

public class UDSNegativeResponse extends UDSResponse {
    private byte rejectedSid;
    private NegativeResponseCode responseCode;

    public UDSNegativeResponse() {

    }

    public UDSNegativeResponse(byte rejectedSid, NegativeResponseCode responseCode) {
        this.rejectedSid = rejectedSid;
        this.responseCode = responseCode;
    }

    @Override
    public void read(BitReader reader) throws IOException {
        this.rejectedSid = reader.readByte();

        final byte responseCodeByte = reader.readByte();

        this.responseCode = Arrays.stream(NegativeResponseCode.values()).filter(rc -> rc.getCode() == responseCodeByte)
                .findFirst().orElseThrow(() -> new UnsupportedOperationException("Unsupported response code "
                        + responseCodeByte));
    }

    @Override
    public void write(BitWriter writer) throws IOException {
        writer.write(rejectedSid & 0xFF);
        writer.write(this.responseCode.getCode() & 0xFF);
    }

    public byte getRejectedSid() {
        return rejectedSid;
    }

    public NegativeResponseCode getResponseCode() {
        return responseCode;
    }

    public void setResponseCode(NegativeResponseCode responseCode) {
        this.responseCode = responseCode;
    }

    @Override
    public String toString() {
        return "sid=0x" + Integer.toHexString(rejectedSid & 0xFF) + " reason=" + responseCode.name();
    }
}
