package com.github.manevolent.atlas.protocol.j2534.tactrix;

import com.github.manevolent.atlas.protocol.can.CANArbitrationId;
import com.github.manevolent.atlas.protocol.can.CANFrame;
import com.github.manevolent.atlas.protocol.isotp.ISOTPFrame;

import java.io.InputStream;

public class OpenPort2ISOTPFrameReader extends OpenPort2FrameReader<ISOTPFrame> {
    public OpenPort2ISOTPFrameReader(InputStream inputStream) {
        super(inputStream);
    }

    @Override
    protected ISOTPFrame createFrame(byte[] header, int arbitrationId, byte[] data) {
        return new Frame(header, new CANArbitrationId(arbitrationId), data);
    }

    public static class Frame extends ISOTPFrame {
        private final byte[] header;

        private Frame(byte[] header, CANArbitrationId arbitrationId, byte[] body) {
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
