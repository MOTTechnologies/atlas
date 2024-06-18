package com.github.manevolent.atlas.protocol.j2534.tactrix;

import aQute.lib.io.IO;
import com.fazecast.jSerialComm.SerialPort;
import com.github.manevolent.atlas.BasicFrame;
import com.github.manevolent.atlas.FrameReader;
import com.github.manevolent.atlas.FrameWriter;
import com.github.manevolent.atlas.model.Project;
import com.github.manevolent.atlas.protocol.isotp.ISOTPFrame;
import com.github.manevolent.atlas.protocol.j2534.*;
import com.github.manevolent.atlas.protocol.can.CANFrame;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Stream;

public class SerialTactrixOpenPort implements J2534Device {
    private final SerialPort serialPort;
    private final InputStream is;
    private final OutputStream os;

    private final Set<Integer> filters = new HashSet<>();

    public SerialTactrixOpenPort(SerialPort serialPort) {
        this.serialPort = serialPort;
        this.is = serialPort.getInputStream();
        this.os = new BufferedOutputStream(serialPort.getOutputStream());
    }

    private String readResponse(String expected) throws IOException {
        String answer = readLine();
        if (answer.startsWith(expected)) {
            return answer;
        } else {
            if (answer.startsWith("are ")) {
                int errorCode = Integer.parseInt(answer.split(" ")[1]);
                String error = Stream.of(J2534Error.values()).filter(e -> e.getCode() == errorCode)
                        .map(J2534Error::name)
                        .findAny().orElse(Integer.toString(errorCode));
                throw new IOException("error: " + error);
            } else {
                throw new IOException("unexpected response: " + answer);
            }
        }
    }

    private String readLine() throws IOException {
        StringBuilder sb = new StringBuilder();
        int c;

        while ((c = is.read()) >= 0) {
            if (c == '\r') {
                continue;
            }
            if (c == '\n') {
                break;
            }

            sb.append((char)c);
        }

        return sb.toString();
    }

    private void preconnect() throws IOException {
        // Empty the buffer
        int read;
        //noinspection StatementWithEmptyBody
        while (is.available() > 0 && (read = is.read()) >= 0) {
        }

        for (int i = 0; i < 8; i ++) {
            os.write("\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
            os.write("ati\r\n".getBytes(StandardCharsets.US_ASCII));
            os.flush();
        }

        while (true) {
            String versionInformation = readLine();
            if (versionInformation.startsWith("ari")) {
                break;
            }
        }

        os.write("ata\r\n".getBytes(StandardCharsets.US_ASCII));
        os.flush();

        while (true) {
            String answer = readLine();
            if (answer.equals("aro")) {
                break;
            }
        }
    }

    private void connect(int protocol) throws IOException {
        int flags = 0x00000800; // CAN_ID_BOTH
        int baud = 500_000;
        os.write(String.format("ato%d %d %d 0\r\n",
                        protocol,
                        flags,
                        baud)
                .getBytes(StandardCharsets.US_ASCII));
        os.flush();

        readResponse("aro");
    }

    private void setupPassthroughCAN(CANFilter... filters) throws IOException {
        int protocol = 5;

        // PASS_FILTER
        // Allows matching messages into the receive queue. This filter type is only valid on non-ISO 15765 channels
        int filterType = 0x01;

        // ISO15765_FRAME_PAD
        // pad all flow controlled messages to a full CAN frame using zeroes
        int txFlags = 0x00000040;

        int maskSize = 4;

        int index = 0;
        for (CANFilter filter : filters) {
            os.write(String.format("atf%d %d %d %d\r\n",
                    protocol,
                    filterType,
                    txFlags,
                    maskSize
            ).getBytes(StandardCharsets.US_ASCII));

            os.write(filter.getMask());
            os.write(filter.getPattern());
            os.flush();

            readResponse(String.format("arf%d %d 0", protocol, index));
            this.filters.add(index);
            index ++;
        }
    }

    private void setupPassthroughISOTP(ISOTPFilter... filters) throws IOException {
        int protocol = 6;

        // FLOW_FILTER
        int filterType = 0x03;

        // ISO15765_FRAME_PAD
        // pad all flow controlled messages to a full CAN frame using zeroes
        int txFlags = 0x00000040;

        int maskSize = 4;

        int index = 0;
        for (ISOTPFilter filter : filters) {
            if (filter.getFlow() == null || filter.getMask() == null || filter.getPattern() == null)
                // Invalid filter, skip it
                continue;

            os.write(String.format("atf%d %d %d %d\r\n",
                    protocol,
                    filterType,
                    txFlags,
                    maskSize
            ).getBytes(StandardCharsets.US_ASCII));

            os.write(filter.getMask());
            os.write(filter.getPattern());
            os.write(filter.getFlow()); // allowed as we set FLOW_FILTER
            os.flush();

            readResponse(String.format("arf%d %d 0", protocol, index));
            this.filters.add(index);
            index ++;
        }
    }


    @Override
    public CANDevice openCAN() throws IOException {
        return openCAN(CAN_ALL);
    }

    @Override
    public CANDevice openCAN(CANFilter... filters) throws IOException {
        if (!serialPort.isOpen() && !serialPort.openPort()) {
            throw new IOException("Failed to open serial port " + serialPort.getSystemPortPath());
        }

        preconnect();
        connect(J2534Protocol.CAN.getCode());
        setupPassthroughCAN(filters);

        return new CANDevice() {
            @Override
            public FrameReader<CANFrame> reader() {
                return new OpenPort2CANFrameReader(is);
            }

            @Override
            public FrameWriter<CANFrame> writer() {
                return new OpenPort2CANFrameWriter(os);
            }

            @Override
            public void close() throws IOException {
                serialPort.closePort();

                is.close();
                os.close();
            }
        };
    }

    @Override
    public ISOTPDevice openISOTOP(ISOTPFilter... filters) throws IOException {
        if (!serialPort.isOpen() && !serialPort.openPort()) {
            throw new IOException("Failed to open serial port " + serialPort.getSystemPortPath() +
                    ": error code 0x" + Integer.toHexString(serialPort.getLastErrorCode()));
        }

        preconnect();
        connect(J2534Protocol.ISO15765.getCode());
        setupPassthroughISOTP(filters);

        OpenPort2ISOTPFrameReader reader = new OpenPort2ISOTPFrameReader(is);
        OpenPort2ISOTPFrameWriter writer = new OpenPort2ISOTPFrameWriter(os);
        return new ISOTPDevice() {
            @Override
            public FrameReader<ISOTPFrame> reader() {
                return reader;
            }

            @Override
            public FrameWriter<BasicFrame> writer() {
                return writer;
            }

            @Override
            public void close() throws IOException {
                SerialTactrixOpenPort.this.close();
            }
        };
    }

    @Override
    public void setConfig(int protocol, int parameter, int value) throws IOException {
        os.write(String.format("ats%d %d %d\r\n",
                protocol,
                parameter,
                value
        ).getBytes(StandardCharsets.US_ASCII));
        os.flush();

        readResponse("aro");

        int set = getConfig(protocol, parameter);
        if (set != value) {
            throw new IOException("Unexpected value for parameter " + parameter + ": " + set + " != " + value);
        }
    }


    @Override
    public int getConfig(int protocol, int parameter) throws IOException {
        os.write(String.format("atg%d %d %d\r\n",
                protocol,
                parameter,
                0
        ).getBytes(StandardCharsets.US_ASCII));
        os.flush();

        String answer = readResponse(String.format("arg%d %d ", protocol, parameter));
        String[] parts = answer.split(" ");
        return Integer.parseInt(parts[2]);
    }

    @Override
    public void close() throws IOException {
        serialPort.closePort();
    }

    public enum CommunicationMode {
        SERIAL_DEVICE,
        UNIX_SOCKET
    }

    public static class SerialPortDescriptor implements J2534DeviceDescriptor {
        private final SerialPort port;

        public SerialPortDescriptor(SerialPort port) {
            this.port = port;
        }

        public SerialPort getPort() {
            return port;
        }

        public String getName() {
            return port.getSystemPortPath();
        }

        // See: https://github.com/Fazecast/jSerialComm/wiki/Java-InputStream-and-OutputStream-Interfacing-Usage-Example
        @Override
        public J2534Device createDevice(Project project) {
            SerialPort serialPort = port;
            serialPort.setComPortTimeouts(SerialPort.TIMEOUT_READ_SEMI_BLOCKING, 0, 0);
            return new SerialTactrixOpenPort(serialPort);
        }

        @Override
        public String toString() {
            return getName();
        }

        @Override
        public boolean equals(Object obj) {
            return obj instanceof SerialPortDescriptor spd
                    && spd.getName().equals(getName());
        }
    }

}
