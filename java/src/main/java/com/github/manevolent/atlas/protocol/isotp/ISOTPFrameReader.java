package com.github.manevolent.atlas.protocol.isotp;

import com.github.manevolent.atlas.FrameReader;
import com.github.manevolent.atlas.logging.Log;
import com.github.manevolent.atlas.protocol.can.CANFrame;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeoutException;
import java.util.logging.Level;

public class ISOTPFrameReader implements FrameReader<ISOTPFrame> {
    private final FrameReader<CANFrame> canReader;
    private final Map<Integer, ISOTPPeer> peers = new HashMap<>();

    public ISOTPFrameReader(FrameReader<CANFrame> canReader) {
        this.canReader = canReader;
    }

    @Override
    public ISOTPFrame read() throws IOException, TimeoutException {
        CANFrame canFrame;
        while (true) {
            canFrame = canReader.read();
            if (canFrame.getLength() <= 0) {
                continue;
            }

            int id = canFrame.getArbitrationId();
            ISOTPPeer peer = peers.computeIfAbsent(id, ISOTPPeer::new);
            ISOTPWireFrame wireFrame = new ISOTPWireFrame();

            try {
                wireFrame.read(canFrame.bitReader());
            } catch (Exception ex) {
                Log.can().log(Level.WARNING, "Problem reading ISO-TP frame " + canFrame + ": "
                        + ex.getMessage(), ex);
                continue;
            }

            ISOTPFrame fullFrame = peer.handleFrame(wireFrame.getSubFrame());
            if (fullFrame != null) {
                return fullFrame;
            }
        }
    }

    @Override
    public void close() throws IOException {
        canReader.close();
    }
}
