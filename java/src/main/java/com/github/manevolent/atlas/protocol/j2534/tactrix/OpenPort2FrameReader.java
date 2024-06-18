package com.github.manevolent.atlas.protocol.j2534.tactrix;

import com.fazecast.jSerialComm.SerialPortTimeoutException;
import com.github.manevolent.atlas.*;
import com.github.manevolent.atlas.logging.Log;
import com.github.manevolent.atlas.protocol.can.CANArbitrationId;
import com.github.manevolent.atlas.protocol.can.CANFrame;
import com.github.manevolent.atlas.protocol.can.CANFrameReader;
import com.github.manevolent.atlas.protocol.isotp.ISOTPFrame;
import com.github.manevolent.atlas.protocol.isotp.ISOTPWireFrame;
import com.github.manevolent.atlas.protocol.j2534.J2534Error;
import org.checkerframework.checker.units.qual.C;

import java.io.*;
import java.util.Arrays;
import java.util.concurrent.TimeoutException;
import java.util.logging.Level;

// Much appreciation for https://github.com/brandonros/rust-tactrix-openport/blob/master/src/lib.rs
public abstract class OpenPort2FrameReader<F extends Frame> implements FrameReader<F>, Closeable {
    /**
     * "ar" in ASCII
     */
    private static final byte[] READ_DATA_HEADER = new byte[] {
            0x61,
            0x72
    };

    /**
     * "are" in ASCII
     */
    private static final byte READ_DATA_HEADER_ERROR = (byte) 0x65;

    private static final byte OK_HEADER = (byte) 0x6F;

    private final InputStream inputStream;

    private boolean closed;

    public OpenPort2FrameReader(InputStream inputStream) {
        this.inputStream = inputStream;
    }

    protected abstract F createFrame(byte[] header, int arbitrationId, byte[] data);

    private int readHeaderChar() throws IOException {
        int data = inputStream.read();
        if (data < 0) {
            throw new EOFException("End of file while reading header character");
        }
        return data;
    }

    private void readHeaderChar(char c) throws IOException {
        int data = readHeaderChar();
        if (data != c) {
            throw new IllegalArgumentException((char)(data & 0xFF) + " != " + c);
        }
    }

    @Override
    public synchronized F read() throws IOException, TimeoutException {
        while (!closed) {
            try {
                readHeaderChar('a');
            } catch (SerialPortTimeoutException ex) {
                continue;
            }

            readHeaderChar('r');

            int i = readHeaderChar();
            char b = (char) (i & 0xFF);
            if (b == '5' || b == '6') {
                int size = inputStream.read();
                if (size < 0) {
                    throw new EOFException("Unexpected frame size: " + size);
                }

                byte[] frame = inputStream.readNBytes(size);
                if (size != frame.length) {
                    throw new EOFException("Unexpected frame size: " + size + " != " + frame.length);
                }

                BitReader frameReader = new BitReader(frame);
                byte[] header = new byte[5];
                frameReader.read(header);
                int arbitrationId = frameReader.readInt();
                byte[] body = frameReader.readRemaining();
                return createFrame(header, arbitrationId, body);
            } else if (b == OK_HEADER) {
                while ((char) inputStream.read() != '\n') {
                    // Do nothing, just consume this frame
                }
            } else if (b == READ_DATA_HEADER_ERROR) {
                StringBuilder sb = new StringBuilder();
                while (true) {
                    char c = (char) inputStream.read();
                    if (c == ' ') continue;
                    if (c == '\r') continue;
                    if (c == '\n') break;

                    sb.append(c);
                }
                int code = Integer.parseInt(sb.toString());
                J2534Error error = Arrays.stream(J2534Error.values()).filter(err -> err.getCode() == code)
                        .findFirst().orElse(null);

                if (error == J2534Error.ERR_TIMEOUT) {
                    throw new TimeoutException();
                }

                throw new IOException(code + "/" + error);
            } else {
                throw new IllegalArgumentException("Unexpected header: " + b);
            }
        }

        throw new EOFException("closed");
    }

    @Override
    public void close() throws IOException {
        closed = true;
        inputStream.close();
    }
}
