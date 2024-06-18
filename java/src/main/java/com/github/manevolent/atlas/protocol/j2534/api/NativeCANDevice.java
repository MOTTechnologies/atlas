package com.github.manevolent.atlas.protocol.j2534.api;

import com.github.manevolent.atlas.FrameReader;
import com.github.manevolent.atlas.FrameWriter;
import com.github.manevolent.atlas.protocol.can.CANFrame;
import com.github.manevolent.atlas.protocol.j2534.CANDevice;

import java.io.IOException;

public class NativeCANDevice implements CANDevice {
    @Override
    public FrameReader<CANFrame> reader() {
        return null;
    }

    @Override
    public FrameWriter<CANFrame> writer() {
        return null;
    }

    @Override
    public void close() throws IOException {

    }
}
