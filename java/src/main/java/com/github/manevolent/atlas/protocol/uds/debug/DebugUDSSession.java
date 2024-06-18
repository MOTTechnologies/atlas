package com.github.manevolent.atlas.protocol.uds.debug;

import com.github.manevolent.atlas.Address;
import com.github.manevolent.atlas.BasicFrame;
import com.github.manevolent.atlas.FrameReader;
import com.github.manevolent.atlas.FrameWriter;
import com.github.manevolent.atlas.protocol.can.CANArbitrationId;
import com.github.manevolent.atlas.protocol.isotp.ISOTPFrame;
import com.github.manevolent.atlas.protocol.j2534.ISOTPDevice;
import com.github.manevolent.atlas.protocol.uds.*;

import com.github.manevolent.atlas.protocol.uds.flag.NegativeResponseCode;
import com.github.manevolent.atlas.protocol.uds.request.UDSClearDTCInformationRequest;
import com.github.manevolent.atlas.protocol.uds.request.UDSDefineDataIdentifierRequest;
import com.github.manevolent.atlas.protocol.uds.request.UDSECUResetRequest;
import com.github.manevolent.atlas.protocol.uds.request.UDSReadDataByIDRequest;
import com.github.manevolent.atlas.protocol.uds.response.*;

import java.io.EOFException;
import java.io.IOException;
import java.util.concurrent.BlockingDeque;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.TimeUnit;


public class DebugUDSSession extends AsyncUDSSession
        implements FrameReader<UDSFrame>, FrameWriter<UDSBody> {

    private final BlockingDeque<UDSBody> replyQueue = new LinkedBlockingDeque<>();

    private int num = 0;

    public static final UDSComponent COMPONENT = new UDSComponent() {
        @Override
        public CANArbitrationId getSendAddress() {
            return new CANArbitrationId(0xB0000); // boo
        }

        @Override
        public CANArbitrationId getReplyAddress() {
            return new CANArbitrationId(0x000F); // OOF! says the ECU when you scare it
        }
    };

    public DebugUDSSession() {
        super(new ISOTPDevice() {
            @Override
            public FrameReader<ISOTPFrame> reader() {
                return null;
            }

            @Override
            public FrameWriter<BasicFrame> writer() {
                return null;
            }

            @Override
            public void close() throws IOException {

            }
        });
    }

    @Override
    public FrameReader<UDSFrame> reader() throws IOException {
        return this;
    }

    @Override
    public FrameWriter<UDSBody> writer() throws IOException {
        return this;
    }

    @Override
    public UDSFrame read() throws IOException {
        UDSFrame frame = new UDSFrame(UDSProtocol.STANDARD);
        UDSBody body;
        try {
            body = replyQueue.poll(1000L, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            throw new EOFException("Interrupted");
        }

        if (body == null) {
            num++;
            int idx = num % 3;
            if (idx == 0) {
                frame.setBody(new UDSReadDataByIDRequest(num));
            } else if (idx == 1) {
                frame.setBody(new UDSNegativeResponse((byte) 0, NegativeResponseCode.VOLTAGE_TOO_LOW));
            } else if (idx == 2) {
                frame.setBody(new UDSUnknownBody());
            }
        } else {
            frame.setBody(body);
        }

        frame.setAddress(COMPONENT.getReplyAddress());
        frame.setDirection(UDSFrame.Direction.READ);

        onUDSFrameRead(frame);

        return frame;
    }

    @Override
    public void write(Address address, UDSBody frame) throws IOException {
        UDSFrame write = new UDSFrame(UDSProtocol.STANDARD, frame);

        write.setAddress(address);
        write.setDirection(UDSFrame.Direction.WRITE);

        onUDSFrameWrite(write);

        // Handle stuff
        if (frame instanceof UDSDefineDataIdentifierRequest) {
            replyQueue.add(new UDSDefineDataIdentifierResponse());
        } else if (frame instanceof UDSClearDTCInformationRequest) {
            replyQueue.add(new UDSClearDTCInformationResponse());
        } else if (frame instanceof UDSECUResetRequest) {
            replyQueue.add(new UDSECUResetResponse());
        } else if (frame instanceof UDSReadDataByIDRequest) {
            replyQueue.add(new UDSReadDataByIDResponse(
                    0x1234,
                    new byte[] { 0x12, 0x34 }
            ));
        }
    }
}
