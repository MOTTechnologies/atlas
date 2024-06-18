package com.github.manevolent.atlas.protocol.j2534.tactrix;

import com.github.manevolent.atlas.Frame;
import com.github.manevolent.atlas.protocol.can.CANFrame;
import java.io.InputStream;

public class OpenPort2CANFrameReader extends OpenPort2FrameReader<CANFrame> {
    public OpenPort2CANFrameReader(InputStream inputStream) {
        super(inputStream);
    }

    @Override
    protected CANFrame createFrame(byte[] header, int arbitrationId, byte[] data) {
        return new Frame(header, arbitrationId, data);
    }

    public static class Frame extends CANFrame {
        private final byte[] header;

        private Frame(byte[] header, int arbitrationId, byte[] body) {
            super(arbitrationId, body);
            this.header = header;
        }

        public byte[] getHeader() {
            return header;
        }

        @Override
        public String toString() {
            return "op2header=" + com.github.manevolent.atlas.Frame.toHexString(header)
                    + " " + super.toString();
        }
    }
}
