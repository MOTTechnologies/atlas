package com.github.manevolent.atlas.protocol.uds.request;

import com.github.manevolent.atlas.BitReader;
import com.github.manevolent.atlas.BitWriter;
import com.github.manevolent.atlas.protocol.uds.flag.DiagnosticSessionType;
import com.github.manevolent.atlas.protocol.uds.UDSRequest;
import com.github.manevolent.atlas.protocol.uds.response.UDSDiagSessionControlResponse;

import java.io.IOException;
import java.util.Arrays;

public class UDSDiagSessionControlRequest extends UDSRequest<UDSDiagSessionControlResponse> {
    private int code;

    public UDSDiagSessionControlRequest() {

    }

    public UDSDiagSessionControlRequest(int code) {
        this.code = code;
    }

    public UDSDiagSessionControlRequest(DiagnosticSessionType type) {
        this.code = type.getCode();
    }

    @Override
    public void read(BitReader reader) throws IOException {
        code = reader.readByte() & 0xFF;
    }

    @Override
    public void write (BitWriter writer) throws IOException {
        writer.write(code & 0xFF);
    }

    public DiagnosticSessionType getSessionType() {
        return Arrays.stream(DiagnosticSessionType.values())
                .filter(sf -> sf.getCode() == this.code).findFirst()
                .orElse(null);
    }

    @Override
    public String toString() {
        DiagnosticSessionType found = getSessionType();

        if (found != null) {
            return found.name();
        } else {
            return String.format("Unknown 0x%02X", code);
        }
    }
}
