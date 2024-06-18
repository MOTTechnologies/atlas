package com.github.manevolent.atlas.protocol.j2534.tactrix;

import com.github.manevolent.atlas.Address;
import com.github.manevolent.atlas.BasicFrame;
import com.github.manevolent.atlas.FrameWriter;
import com.github.manevolent.atlas.protocol.can.CANArbitrationId;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

// Much appreciation for https://github.com/brandonros/rust-tactrix-openport/blob/master/src/lib.rs
public class OpenPort2ISOTPFrameWriter implements FrameWriter<BasicFrame>, Closeable {
    private static final byte channelId = 6;
    private static final int txFlags = 0x00000040;

    private final OutputStream outputStream;
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    public OpenPort2ISOTPFrameWriter(OutputStream outputStream) {
        this.outputStream = outputStream;
    }

    @Override
    public void close() throws IOException {
        outputStream.close();
    }

    @Override
    public synchronized void write(Address address, BasicFrame frame) throws IOException {
        buffer.reset();

        String command = String.format("att%d %d %d\r\n",
                channelId,
                4 + frame.getLength(), // 8 bytes CAN + 4 bytes arb ID
                txFlags
        );

        buffer.write(command.getBytes(StandardCharsets.US_ASCII));

        int arbitrationId;
        if (address instanceof CANArbitrationId) {
            arbitrationId = ((CANArbitrationId) address).getArbitrationId();
        } else {
            throw new IllegalArgumentException("Arbitration ID not supplied");
        }

        byte[] arbitrationIdBytes = new byte[4];
        arbitrationIdBytes[0] = (byte) ((arbitrationId >> 24) & 0xFF);
        arbitrationIdBytes[1] = (byte) ((arbitrationId >> 16) & 0xFF);
        arbitrationIdBytes[2] = (byte) ((arbitrationId >> 8) & 0xFF);
        arbitrationIdBytes[3] = (byte) ((arbitrationId) & 0xFF);
        buffer.write(arbitrationIdBytes);

        buffer.write(frame.getData());

        buffer.writeTo(outputStream);
        outputStream.flush();
    }
}
