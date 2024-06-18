package com.github.manevolent.atlas.protocol.uds.request;

import com.github.manevolent.atlas.BitReader;
import com.github.manevolent.atlas.BitWriter;
import com.github.manevolent.atlas.Frame;
import com.github.manevolent.atlas.protocol.uds.flag.DTCControlMode;
import com.github.manevolent.atlas.protocol.uds.UDSRequest;
import com.github.manevolent.atlas.protocol.uds.response.UDSControlDTCSettingsResponse;

import java.io.IOException;
import java.util.Arrays;

public class UDSControlDTCSettingsRequest extends UDSRequest<UDSControlDTCSettingsResponse> {
    private int code;
    private byte[] records;

    public UDSControlDTCSettingsRequest() {
        this.code = 0;
        this.records = null;
    }

    public UDSControlDTCSettingsRequest(int code, byte[] records) {
        this.code = code;
        this.records = records;
    }

    public UDSControlDTCSettingsRequest(int code) {
        this(code, new byte[0]);
    }

    public UDSControlDTCSettingsRequest(DTCControlMode mode) {
        this(mode.getCode());
    }

    public UDSControlDTCSettingsRequest(DTCControlMode mode, byte[] records) {
        this(mode.getCode(), records);
    }

    public int getCode() {
        return code;
    }

    public byte[] getRecords() {
        return records;
    }

    @Override
    public void write(BitWriter writer) throws IOException {
        writer.write(code & 0xFF);
        writer.write(records);
    }

    @Override
    public void read(BitReader reader) throws IOException {
        code = reader.readByte() & 0xFF;
        records = reader.readRemaining();
    }

    @Override
    public String toString() {
        DTCControlMode found = Arrays.stream(DTCControlMode.values())
                .filter(sf -> sf.getCode() == this.code).findFirst()
                .orElse(null);

        String string;
        if (found != null) {
            string = found.name();
        } else {
            string = String.format("Unknown 0x%02X", code);
        }

        return String.format("mode=%s records=%s", string, Frame.toHexString(records));
    }
}
