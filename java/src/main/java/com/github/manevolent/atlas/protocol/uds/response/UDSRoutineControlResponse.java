package com.github.manevolent.atlas.protocol.uds.response;

import com.github.manevolent.atlas.BitReader;
import com.github.manevolent.atlas.BitWriter;
import com.github.manevolent.atlas.Frame;
import com.github.manevolent.atlas.protocol.uds.flag.RoutineControlSubFunction;
import com.github.manevolent.atlas.protocol.uds.UDSResponse;

import java.io.IOException;
import java.util.Arrays;

// See: https://piembsystech.com/routinecontrol-0x31-service-uds-protocol/
public class UDSRoutineControlResponse extends UDSResponse implements Frame {
    private int controlFunction;
    private int routineId;
    private byte[] data;

    public UDSRoutineControlResponse() {

    }

    public UDSRoutineControlResponse(int controlFunction, int routineId, byte[] data) {
        this.controlFunction = controlFunction;
        this.routineId = routineId;
        this.data = data;
    }

    public UDSRoutineControlResponse(int controlFunction, int routineId) {
        this.controlFunction = controlFunction;
        this.routineId = routineId;
        this.data = new byte[0];
    }

    @Override
    public void read(BitReader reader) throws IOException {
        controlFunction = reader.readByte() & 0xFF;
        routineId = reader.readShort() & 0xFFFF;
        data = reader.readRemaining();
    }

    @Override
    public void write(BitWriter writer) throws IOException {
        writer.write(controlFunction & 0xFF);
        writer.writeShort((short) (routineId & 0xFFFF));
        writer.write(data);
    }

    @Override
    public byte[] getData() {
        return data;
    }

    public int getRoutineId() {
        return routineId;
    }

    public int getControlFunction() {
        return controlFunction;
    }

    @Override
    public String toString() {
        String controlRoutine = Arrays.stream(RoutineControlSubFunction.values())
                .filter(sf -> sf.getCode() == this.controlFunction)
                .map(Enum::name)
                .findFirst()
                .orElse(Integer.toString(this.controlFunction));

        return "func=" + controlRoutine + " routineId=" + Integer.toHexString(routineId).toUpperCase()
                + " data=" + toHexString();
    }

}
