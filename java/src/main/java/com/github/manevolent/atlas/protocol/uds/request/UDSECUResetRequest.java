package com.github.manevolent.atlas.protocol.uds.request;

import com.github.manevolent.atlas.BitReader;
import com.github.manevolent.atlas.BitWriter;
import com.github.manevolent.atlas.protocol.uds.flag.ECUResetMode;
import com.github.manevolent.atlas.protocol.uds.UDSRequest;
import com.github.manevolent.atlas.protocol.uds.response.UDSECUResetResponse;

import java.io.IOException;
import java.util.Arrays;

public class UDSECUResetRequest extends UDSRequest<UDSECUResetResponse> {
    private int resetMode;

    public UDSECUResetRequest() {

    }

    public UDSECUResetRequest(int mode) {
        this.resetMode = mode;
    }

    public UDSECUResetRequest(ECUResetMode mode) {
        this.resetMode = mode.getCode();
    }

    @Override
    public void write(BitWriter writer) throws IOException {
        writer.write(resetMode & 0xFF);
    }

    @Override
    public void read(BitReader reader) throws IOException {
        this.resetMode = reader.readByte();
    }

    @Override
    public String toString() {
        String resetMode = Arrays.stream(ECUResetMode.values())
                .filter(sf -> sf.getCode() == this.resetMode)
                .map(Enum::toString)
                .findFirst()
                .orElse(Integer.toString(this.resetMode));

        return "mode=" + resetMode;
    }
}
