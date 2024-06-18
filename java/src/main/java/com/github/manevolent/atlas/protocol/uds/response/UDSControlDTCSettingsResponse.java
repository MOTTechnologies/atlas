package com.github.manevolent.atlas.protocol.uds.response;

import com.github.manevolent.atlas.BitReader;
import com.github.manevolent.atlas.BitWriter;
import com.github.manevolent.atlas.protocol.uds.flag.DTCControlMode;
import com.github.manevolent.atlas.protocol.uds.UDSResponse;

import java.io.IOException;
import java.util.Arrays;

public class UDSControlDTCSettingsResponse extends UDSResponse {
    private int code;

    public UDSControlDTCSettingsResponse() {

    }

    public UDSControlDTCSettingsResponse(int code) {
        this.code = code;
    }

    public UDSControlDTCSettingsResponse(DTCControlMode mode) {
        this.code = mode.getCode();
    }

    @Override
    public void write(BitWriter writer) throws IOException {
        writer.write(code);
    }

    @Override
    public void read(BitReader reader) throws IOException {
        code = reader.readByte() & 0xFF;
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

        return String.format("mode=%s", string);
    }
}
