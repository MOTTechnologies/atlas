package com.github.manevolent.atlas.protocol.uds.response;

import com.github.manevolent.atlas.BitReader;
import com.github.manevolent.atlas.BitWriter;
import com.github.manevolent.atlas.Frame;
import com.github.manevolent.atlas.protocol.uds.flag.DiagnosticSessionType;
import com.github.manevolent.atlas.protocol.uds.UDSResponse;

import java.io.IOException;
import java.util.Arrays;

public class UDSDiagSessionControlResponse extends UDSResponse implements Frame {
    private int code;
    private int minResponseTime;
    private int maxResponseTime;

    public UDSDiagSessionControlResponse() {

    }

    public UDSDiagSessionControlResponse(int code, int minResponseTime, int maxResponseTime) {
        this.code = code;
        this.minResponseTime = minResponseTime;
        this.maxResponseTime = maxResponseTime;
    }

    public UDSDiagSessionControlResponse(DiagnosticSessionType sessionType, int minResponseTime, int maxResponseTime) {
        this(sessionType.getCode(), minResponseTime, maxResponseTime);
    }

    @Override
    public void read(BitReader reader) throws IOException {
        code = reader.readByte() & 0xFF;

        if (reader.available() > 0) {
            minResponseTime = reader.readShort() & 0xFFFF;
            maxResponseTime = reader.readShort() & 0xFFFF;
        }
    }

    @Override
    public void write(BitWriter writer) throws IOException {
        writer.write(code & 0xFF);
        writer.writeShort((short) (minResponseTime & 0xFFFF));
        writer.writeShort((short) (maxResponseTime & 0xFFFF));
    }

    public int getMinResponseTime() {
        return minResponseTime;
    }

    public int getMaxResponseTime() {
        return maxResponseTime;
    }

    DiagnosticSessionType getSessionType() {
        return Arrays.stream(DiagnosticSessionType.values())
                .filter(sf -> sf.getCode() == this.code).findFirst()
                .orElse(null);
    }

    @Override
    public String toString() {
        DiagnosticSessionType found = getSessionType();
        if (found != null) {
            return found.name() + " min=" + minResponseTime + "ms max=" + maxResponseTime + "ms";
        } else {
            return String.format("Unknown 0x%02X", code)
                    + " min=" + minResponseTime + "ms max=" + maxResponseTime + "ms";
        }
    }
}
