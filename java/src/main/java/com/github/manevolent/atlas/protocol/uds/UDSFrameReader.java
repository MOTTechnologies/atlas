package com.github.manevolent.atlas.protocol.uds;

import com.github.manevolent.atlas.Addressed;
import com.github.manevolent.atlas.Frame;
import com.github.manevolent.atlas.FrameReader;
import com.github.manevolent.atlas.logging.Log;

import java.io.IOException;
import java.util.concurrent.TimeoutException;
import java.util.logging.Level;

public class UDSFrameReader implements FrameReader<UDSFrame> {
    private final FrameReader<?> transport;
    private final UDSProtocol protocol;

    public UDSFrameReader(FrameReader<?> transport, UDSProtocol protocol) {
        this.transport = transport;
        this.protocol = protocol;
    }

    protected void onFrameRead(UDSFrame frame) {

    }

    @Override
    public UDSFrame read() throws IOException, TimeoutException {
        Frame frame = transport.read();
        if (frame == null || frame.getLength() <= 0) {
            return null;
        }
        UDSFrame udsFrame = convert(protocol, frame);
        if (udsFrame == null) {
            return null;
        }
        Log.can().log(Level.FINER, udsFrame.toString());
        onFrameRead(udsFrame);
        return udsFrame;
    }

    @Override
    public void close() throws IOException {
        transport.close();
    }

    public static UDSFrame convert(UDSProtocol protocol, Frame frame) throws IOException {
        if (frame == null) {
            return null;
        }

        UDSFrame udsFrame = new UDSFrame(protocol);
        udsFrame.setDirection(UDSFrame.Direction.READ);

        if (frame instanceof Addressed) {
            udsFrame.setAddress(((Addressed) frame).getAddress());
        }

        try {
            udsFrame.read(frame.bitReader());
        } catch (Exception ex) {
            throw new IOException("Problem reading frame " + frame.toHexString(), ex);
        }

        return udsFrame;
    }
}
