package com.github.manevolent.atlas.protocol.uds.request;

import com.github.manevolent.atlas.BitReader;
import com.github.manevolent.atlas.BitWriter;
import com.github.manevolent.atlas.Frame;
import com.github.manevolent.atlas.protocol.uds.flag.RoutineControlSubFunction;
import com.github.manevolent.atlas.protocol.uds.UDSRequest;
import com.github.manevolent.atlas.protocol.uds.response.UDSRoutineControlResponse;

import java.io.IOException;
import java.util.Arrays;

// See: https://piembsystech.com/routinecontrol-0x31-service-uds-protocol/
public class UDSRoutineControlRequest
        extends UDSRequest<UDSRoutineControlResponse> implements Frame {
    private int controlFunction;
    private int routineId;
    private byte[] data;

    public UDSRoutineControlRequest() {

    }

    public UDSRoutineControlRequest(int controlFunction, int routineId) {
        this.controlFunction = controlFunction;
        this.routineId = routineId;
        this.data = new byte[0];
    }

    public UDSRoutineControlRequest(int controlFunction, int routineId, byte[] data) {
        this.controlFunction = controlFunction;
        this.routineId = routineId;
        this.data = data;
    }

    public UDSRoutineControlRequest(RoutineControlSubFunction subFunction, int routineId) {
        this.controlFunction = subFunction.getCode();
        this.routineId = routineId;
        this.data = new byte[0];
    }

    public UDSRoutineControlRequest(RoutineControlSubFunction subFunction, int routineId, byte[] data) {
        this.controlFunction = subFunction.getCode();
        this.routineId = routineId;
        this.data = data;
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

    public int getControlFunctionId() {
        return controlFunction;
    }

    public int getRoutineId() {
        return routineId;
    }

    public RoutineControlSubFunction getSubFunction() {
        return Arrays.stream(RoutineControlSubFunction.values())
                .filter(sf -> sf.getCode() == this.controlFunction)
                .findFirst()
                .orElse(null);
    }

    @Override
    public String toString() {
        RoutineControlSubFunction subFunction = getSubFunction();
        String controlRoutine;
        if (subFunction != null) {
            controlRoutine = subFunction.name();
        } else {
            controlRoutine = Integer.toString(this.controlFunction);
        }
        return "func=" + controlRoutine + " routineId=" + Integer.toHexString(routineId & 0xFFFF).toUpperCase()
                + " data=" + toHexString();
    }

}
