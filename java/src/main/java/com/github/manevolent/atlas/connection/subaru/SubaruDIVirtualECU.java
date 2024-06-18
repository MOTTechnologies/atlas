package com.github.manevolent.atlas.connection.subaru;

import com.github.manevolent.atlas.*;
import com.github.manevolent.atlas.logging.Log;
import com.github.manevolent.atlas.model.Calibration;
import com.github.manevolent.atlas.model.Project;
import com.github.manevolent.atlas.model.crypto.MemoryEncryptionType;
import com.github.manevolent.atlas.model.crypto.SubaruDIMemoryEncryption;
import com.github.manevolent.atlas.protocol.can.CANArbitrationId;
import com.github.manevolent.atlas.protocol.isotp.ISOTPFrame;
import com.github.manevolent.atlas.protocol.j2534.*;
import com.github.manevolent.atlas.protocol.subaru.SubaruDITComponent;
import com.github.manevolent.atlas.protocol.subaru.SubaruProtocols;
import com.github.manevolent.atlas.protocol.subaru.uds.SubaruVendorInfoRecord;
import com.github.manevolent.atlas.protocol.subaru.uds.request.SubaruStatus1Request;
import com.github.manevolent.atlas.protocol.subaru.uds.request.SubaruVendorInfoRequest;
import com.github.manevolent.atlas.protocol.subaru.uds.response.SubaruStatus1Response;
import com.github.manevolent.atlas.protocol.subaru.uds.response.SubaruVendorInfoResponse;
import com.github.manevolent.atlas.protocol.uds.*;
import com.github.manevolent.atlas.protocol.uds.flag.*;
import com.github.manevolent.atlas.protocol.uds.request.*;
import com.github.manevolent.atlas.protocol.uds.response.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import java.nio.ByteBuffer;
import java.util.*;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.logging.Level;

/**
 * A virtual ECU that acts like any typical Renesas-based Subaru DI ECU (2015-2022)
 * Used to run unit tests, so we can be at least somewhat sure we don't brick people's ECUs with bad code
 */
public class SubaruDIVirtualECU implements Runnable {
    private final SubaruDIPlatform platform;
    private Calibration calibration;
    private final UDSProtocol protocol;
    private final byte[] flash;

    private final SubaruDIMemoryEncryption encryption;
    private final byte[] feistelKey;
    private final byte[] gatewayKey, engineKey1;
    private byte[] gatewaySeed, ecuSeed;

    private long transferred = 0L;
    private boolean transferring = false;

    private final LinkedBlockingDeque<Packet> testerToEcu = new LinkedBlockingDeque<>();
    private final LinkedBlockingDeque<Packet> ecuToTester = new LinkedBlockingDeque<>();

    private final Map<Integer, List<DynamicallyDefinedDID>> dids = new HashMap<>();

    private Project project;
    private Thread thread;
    private boolean running;

    private boolean commControlDisabled = false;
    private boolean dtcDisabled = false;

    private UDSSessionState ecuSession = new UDSSessionState();
    private UDSSessionState gatewaySession = new UDSSessionState();

    private boolean gatewayUnlocked = false;

    public SubaruDIVirtualECU(SubaruDIPlatform platform) {
        this.platform = platform;
        this.flash = new byte[(int) (platform.getFlashEnd() - platform.getFlashStart())];
        this.protocol = SubaruProtocols.DIT;

        Random random = new Random(1234123412341234L);
        random.nextBytes(this.gatewayKey = new byte[16]);
        random.nextBytes(this.engineKey1 = new byte[16]);
        random.nextBytes(this.feistelKey = new byte[8]);

        this.encryption = new SubaruDIMemoryEncryption();
    }

    public void setProject(Project project) {
        this.project = project;

        setCalibration(project.getCalibrations().stream()
                .filter(c -> platform.getCalibrationIds().contains(c.getName()))
                .findFirst()
                .orElse(null));
    }

    public byte[] getFeistelKey() {
        return feistelKey;
    }

    public byte[] getEngineKey1() {
        return engineKey1;
    }

    public byte[] getGatewayKey() {
        return gatewayKey;
    }

    public SubaruDIPlatform getPlatform() {
        return platform;
    }

    public J2534DeviceDescriptor getDescriptor() {
        return new DeviceDescriptor();
    }

    public J2534DeviceProvider<?> getDeviceProvider() {
        return new J2534DeviceProvider<>() {
            @Override
            public J2534DeviceDescriptor getDefaultDevice() throws DeviceNotFoundException {
                return null;
            }

            @Override
            public void setDefaultDevice(J2534DeviceDescriptor descriptor) {
                throw new UnsupportedOperationException();
            }

            @Override
            public List<J2534DeviceDescriptor> getAllDevices() {
                return Collections.singletonList(getDescriptor());
            }
        };
    }

    public boolean isRunning() {
        return running;
    }

    private UDSFrame readUdsFrame() throws InterruptedException, IOException {
        Packet packet = testerToEcu.take();
        UDSFrame frame = packet.toUDSFrame();
        frame.setAddress(packet.address);
        //System.out.println(frame);
        return frame;
    }

    @Override
    public void run() {
        try {
            while (!Thread.interrupted() && running) {
                try {
                    handle(readUdsFrame());
                } catch (InterruptedException e) {
                    break;
                } catch (IOException e) {
                    Log.can().log(Level.SEVERE, "Problem handling UDS frame", e);
                }
            }
        } finally {
            running = false;
        }
    }

    /**
     * You can think of this like the CAN bus in the vehicle.
     * @param frame frame sent to the gateway via the OBD2 port.
     * @throws IOException if there's a problem handling the message.
     */
    private void handle(UDSFrame frame) throws IOException {
        UDSBody request = frame.getBody();
        if (frame.getAddress() == SubaruDITComponent.ENGINE_1.getSendAddress()) {
            send(handleEngine1(request), SubaruDITComponent.ENGINE_1.getReplyAddress());
        } else if (frame.getAddress() == SubaruDITComponent.ENGINE_2.getSendAddress()) {
            send(handleEngine2(request), SubaruDITComponent.ENGINE_2.getReplyAddress());
        } else if (frame.getAddress() == SubaruDITComponent.CENTRAL_GATEWAY.getSendAddress()) {
            send(handleGateway(request), SubaruDITComponent.CENTRAL_GATEWAY.getReplyAddress());
        } else if (frame.getAddress() == SubaruDITComponent.BODY_CONTROL.getSendAddress()) {
            send(handleBodyControl(request), SubaruDITComponent.BODY_CONTROL.getReplyAddress());
        } else if (frame.getAddress() == SubaruDITComponent.BROADCAST.getSendAddress()) {
            send(handleGateway(request), SubaruDITComponent.CENTRAL_GATEWAY.getReplyAddress());
            send(handleBodyControl(request), SubaruDITComponent.BODY_CONTROL.getReplyAddress());
            send(handleEngine2(request), SubaruDITComponent.ENGINE_2.getReplyAddress());
            send(handleEngine1(request), SubaruDITComponent.ENGINE_1.getReplyAddress());
        }
    }

    private void send(UDSResponse response, CANArbitrationId replyAddress) throws IOException {
        if (response == null) {
            return;
        }

        UDSFrame frame = new UDSFrame(protocol, response);
        frame.setDirection(UDSFrame.Direction.WRITE);
        frame.setAddress(replyAddress);
        Packet packet = new Packet(replyAddress, BasicFrame.from(frame));
        //System.out.println(frame);
        ecuToTester.add(packet);
    }

    private UDSNegativeResponse error(UDSBody request, NegativeResponseCode code) {
        return new UDSNegativeResponse((byte) (protocol.getSid(request.getClass()) & 0xFF), code);
    }

    private UDSResponse handleGateway(UDSBody request) {
        DiagnosticSessionType sessionType = gatewaySession.getSessionType();
        int securityLevel = gatewaySession.getSecurityLevel();

        if (sessionType == DiagnosticSessionType.DEFAULT_SESSION && gatewayUnlocked) {
            gatewayUnlocked = false;
        }

        UDSResponse response = null;

        if (request instanceof UDSDiagSessionControlRequest diagControl) {
            switch (diagControl.getSessionType()) {
                case EXTENDED_SESSION, DEFAULT_SESSION -> {
                    gatewaySession.setSessionType(diagControl.getSessionType());
                    response = new UDSDiagSessionControlResponse(diagControl.getSessionType(), 50, 500);
                }
                case PROGRAMMING_SESSION -> {
                    return error(request, NegativeResponseCode.SERVICE_NOT_SUPPORTED_IN_SESSION);
                }
            }
        } else if (request instanceof UDSSecurityAccessRequest securityAccess) {
            if (sessionType != DiagnosticSessionType.EXTENDED_SESSION) {
                return error(request, NegativeResponseCode.SERVICE_NOT_SUPPORTED_IN_SESSION);
            }

            switch (securityAccess.getLevel()) {
                case 7 -> {
                    if (securityLevel == 7) {
                        return new UDSSecurityAccessResponse(7);
                    }

                    byte[] seed = new byte[16];
                    new Random(0x12341234DEADBEEFL).nextBytes(seed);
                    response = new UDSSecurityAccessResponse(7, seed);
                    this.gatewaySeed = seed;
                }
                case 8 -> {
                    gatewaySession.setSecurityLevel(7);
                    response = new UDSSecurityAccessResponse(8);
                }
                default -> {
                    return error(request, NegativeResponseCode.SERVICE_NOT_SUPPORTED_IN_SESSION);
                }
            }
        } else if (request instanceof UDSRoutineControlRequest routineControl) {
            // I am not absolutely positive that this is what this routine does, but I am assuming that it is used
            // to unlock access to the various control units in the CAN bus that the OBD2 device doesn't necessarily
            // have direct access to.
            if (sessionType != DiagnosticSessionType.EXTENDED_SESSION || securityLevel != 7) {
                return error(request, NegativeResponseCode.SERVICE_NOT_SUPPORTED_IN_SESSION);
            }

            if (routineControl.getSubFunction() == RoutineControlSubFunction.START_ROUTINE &&
                    routineControl.getRoutineId() == 0x0200) {
                gatewayUnlocked = true;

                response = new UDSRoutineControlResponse(RoutineControlSubFunction.START_ROUTINE.getCode(), 0x0200);
            } else if (routineControl.getSubFunction() == RoutineControlSubFunction.START_ROUTINE &&
                    routineControl.getRoutineId() == 0x0201) {
                // Verify the preparedness to program
                if (!dtcDisabled || !commControlDisabled) {
                    return error(request, NegativeResponseCode.CONDITIONS_NOT_CORRECT);
                } else {
                    response = new UDSRoutineControlResponse(RoutineControlSubFunction.START_ROUTINE.getCode(), 0x0201);
                }
            } else {
                return error(request, NegativeResponseCode.SERVICE_NOT_SUPPORTED);
            }
        } else if (request instanceof UDSTesterPresentRequest) {
            if (sessionType == DiagnosticSessionType.EXTENDED_SESSION) {
                gatewaySession.testerPresent();
            }
        } else if (request instanceof UDSCommunicationControlRequest communicationControlRequest) {
            if (sessionType != DiagnosticSessionType.EXTENDED_SESSION) {
                return error(request, NegativeResponseCode.SERVICE_NOT_SUPPORTED_IN_SESSION);
            }

            return new UDSCommunicationControlResponse(communicationControlRequest.getCommunicationType());
        }

        return response;
    }

    private UDSResponse handleEngine1(UDSBody request) throws IOException {
        DiagnosticSessionType sessionType = ecuSession.getSessionType();
        int securityLevel = ecuSession.getSecurityLevel();

        // Any functions below this statement are typically locked by the gateway unless authorization is provided
        if (!gatewayUnlocked && !(request instanceof UDSDiagSessionControlRequest)) {
            Log.can().log(Level.WARNING, "Dropping request since gateway is locked: " + request);
            return null;
        }

        UDSResponse response = null;

        if (request instanceof UDSDiagSessionControlRequest diagControl) {
            switch (diagControl.getSessionType()) {
                case EXTENDED_SESSION, DEFAULT_SESSION -> {
                    ecuSession.setSessionType(diagControl.getSessionType());
                }
                case PROGRAMMING_SESSION -> {
                    if (securityLevel != 1) {
                        return error(request, NegativeResponseCode.SERVICE_NOT_SUPPORTED_IN_SESSION);
                    }

                    ecuSession.setSessionType(diagControl.getSessionType());
                }
            }

            response = new UDSDiagSessionControlResponse(diagControl.getSessionType(), 50, 500);
        }

        if (request instanceof UDSSecurityAccessRequest securityAccess) {
            if (sessionType != DiagnosticSessionType.EXTENDED_SESSION) {
                return error(request, NegativeResponseCode.SERVICE_NOT_SUPPORTED_IN_SESSION);
            }

            switch (securityAccess.getLevel()) {
                case 1, 3, 5 -> {
                    if (securityLevel != 0) {
                        return new UDSSecurityAccessResponse(1);
                    }

                    byte[] seed = new byte[16];
                    new Random(0x12341234DEADBEEFL).nextBytes(seed);
                    response = new UDSSecurityAccessResponse(securityAccess.getLevel(), seed);
                    this.ecuSeed = seed;
                }
                case 2, 4, 6 -> {
                    ecuSession.setSecurityLevel(1);
                    response = new UDSSecurityAccessResponse(securityAccess.getLevel());
                }
                default -> {
                    return error(request, NegativeResponseCode.SERVICE_NOT_SUPPORTED_IN_SESSION);
                }
            }
        } else if (request instanceof UDSRoutineControlRequest routineControl) {
            if (sessionType == DiagnosticSessionType.DEFAULT_SESSION) {
                return null;
            }

            if (((UDSRoutineControlRequest) request).getSubFunction() != RoutineControlSubFunction.START_ROUTINE) {
                return error(request, NegativeResponseCode.SERVICE_NOT_SUPPORTED);
            }

            if (routineControl.getRoutineId() == 0xFF00) {
                // CLEAR FLASH!
                if (sessionType != DiagnosticSessionType.PROGRAMMING_SESSION) {
                    return error(request, NegativeResponseCode.SERVICE_NOT_SUPPORTED_IN_SESSION);
                } else if (transferring) {
                    return error(request, NegativeResponseCode.CONDITIONS_NOT_CORRECT);
                }

                BitReader bitReader = new BitReader(routineControl.getData());
                long len1 = bitReader.read(4);
                long len2 = bitReader.read(4);
                long addr = bitReader.readInt() & 0xFFFFFFFFL;
                long sz = bitReader.readInt() & 0xFFFFFFFFL;

                if (len1 != 4) {
                    return error(request, NegativeResponseCode.INVALID_MESSAGE_LEN_OR_FORMAT);
                } else if (len2 != 4) {
                    return error(request, NegativeResponseCode.INVALID_MESSAGE_LEN_OR_FORMAT);
                } else if (addr != platform.getFlashStart()) {
                    return error(request, NegativeResponseCode.INVALID_MESSAGE_LEN_OR_FORMAT);
                } else if (sz != platform.getFlashSize()) {
                    return error(request, NegativeResponseCode.INVALID_MESSAGE_LEN_OR_FORMAT);
                }

                Arrays.fill(flash, (byte) 0x5A);

                // The ECU normally takes time to do this, so wait about 5 seconds and reproduce the NRC too
                for (int i = 0; i < 5; i ++) {
                    try {
                        Thread.sleep(1000L);
                    } catch (InterruptedException e) {
                        throw new RuntimeException(e);
                    }

                    try {
                        send(error(request, NegativeResponseCode.RESPONSE_PENDING),
                                SubaruDITComponent.ENGINE_1.getReplyAddress());

                        gatewaySession.testerPresent();
                        ecuSession.testerPresent();
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                }

                response = new UDSRoutineControlResponse(routineControl.getControlFunctionId(),
                        routineControl.getRoutineId(), new byte[0]);
            } else if (routineControl.getRoutineId() == 0xFF01) {
                // Check flash
                if (sessionType != DiagnosticSessionType.PROGRAMMING_SESSION) {
                    return error(request, NegativeResponseCode.SERVICE_NOT_SUPPORTED_IN_SESSION);
                } else if (transferring) {
                    return error(request, NegativeResponseCode.CONDITIONS_NOT_CORRECT);
                }

                Calibration calibration = Calibrations.createCalibration("virtualFlash", flash,
                        MemoryEncryptionType.NONE);
                calibration.getSection().setup(project);

                int code;
                try {
                    code = platform.getChecksum(calibration).validate(calibration) ? 1 : 0;
                } catch (IOException e) {
                    Log.can().log(Level.WARNING, "Problem validating flash", e);
                    code = 0;
                }

                response = new UDSRoutineControlResponse(routineControl.getControlFunctionId(),
                        routineControl.getRoutineId(), new byte[] { (byte) code });
            } else {
                return error(request, NegativeResponseCode.SERVICE_NOT_SUPPORTED);
            }
        } else if (request instanceof UDSDownloadRequest downloadRequest) {
            if (sessionType != DiagnosticSessionType.PROGRAMMING_SESSION) {
                return error(request, NegativeResponseCode.SERVICE_NOT_SUPPORTED_IN_SESSION);
            }

            if (downloadRequest.getDataCompression() != 0) {
                return error(request, NegativeResponseCode.INVALID_MESSAGE_LEN_OR_FORMAT);
            } else if (downloadRequest.getDataEncryption() != 4) {
                return error(request, NegativeResponseCode.INVALID_MESSAGE_LEN_OR_FORMAT);
            } else if (downloadRequest.getMemorySizeBytes() != 4) {
                return error(request, NegativeResponseCode.INVALID_MESSAGE_LEN_OR_FORMAT);
            } else if (downloadRequest.getMemoryAddressBytes() != 4) {
                return error(request, NegativeResponseCode.INVALID_MESSAGE_LEN_OR_FORMAT);
            } else if (downloadRequest.getMemoryAddress() != platform.getFlashStart()) {
                return error(request, NegativeResponseCode.INVALID_MESSAGE_LEN_OR_FORMAT);
            } else if (downloadRequest.getMemorySize() != platform.getFlashSize()) {
                return error(request, NegativeResponseCode.INVALID_MESSAGE_LEN_OR_FORMAT);
            }

            int bufferSize = 256;
            int overhead = 6;
            response = new UDSDownloadResponse(4, bufferSize + overhead);
            transferring = true;
            transferred = 0;

        } else if (request instanceof UDSTransferRequest transferRequest) {
            if (sessionType != DiagnosticSessionType.PROGRAMMING_SESSION) {
                return error(request, NegativeResponseCode.SERVICE_NOT_SUPPORTED_IN_SESSION);
            } else if (transferRequest.getAddress() < platform.getFlashStart()) {
                return error(request, NegativeResponseCode.INVALID_MESSAGE_LEN_OR_FORMAT);
            } else if (transferRequest.getData().length > 256) {
                return error(request, NegativeResponseCode.INVALID_MESSAGE_LEN_OR_FORMAT);
            } else if (transferRequest.getAddress() + transferRequest.getData().length > platform.getFlashEnd()) {
                return error(request, NegativeResponseCode.INVALID_MESSAGE_LEN_OR_FORMAT);
            } else if (!transferring) {
                return error(request, NegativeResponseCode.CONDITIONS_NOT_CORRECT);
            }

            byte[] buffer = transferRequest.getData();
            encryption.decrypt(calibration, buffer);

            long end = transferRequest.getAddress() + transferRequest.getData().length;
            for (long address = transferRequest.getAddress(); address < end; address ++) {
                int index = (int) (address - platform.getFlashStart());
                byte data = flash[index];
                if (data != 0x5A) {
                    Log.can().log(Level.SEVERE, "Tried to overwrite uncleared flash at address " + address);
                    return error(request, NegativeResponseCode.REQUEST_OUT_OF_RANGE);
                }

                flash[index] = buffer[(int) (address - transferRequest.getAddress())];
                transferred++;
            }

            response = new UDSTransferResponse(transferRequest.getIndex());
        } else if (request instanceof UDSTesterPresentRequest) {
            if (sessionType != DiagnosticSessionType.DEFAULT_SESSION) {
                ecuSession.testerPresent();
            }
        } else if (request instanceof UDSTransferExitRequest transferExitRequest) {
            if (request.getLength() != 0) {
                return error(request, NegativeResponseCode.INVALID_MESSAGE_LEN_OR_FORMAT);
            } else if (sessionType != DiagnosticSessionType.PROGRAMMING_SESSION) {
                return error(request, NegativeResponseCode.SERVICE_NOT_SUPPORTED_IN_SESSION);
            } else if (!transferring) {
                return error(request, NegativeResponseCode.CONDITIONS_NOT_CORRECT);
            } else if (transferred != platform.getFlashSize()) {
                return error(request, NegativeResponseCode.CONDITIONS_NOT_CORRECT);
            }

            response = new UDSTransferExitResponse();

            transferring = false;
        } else if (request instanceof UDSControlDTCSettingsRequest controlDTCSettingsRequest) {
            dtcDisabled = controlDTCSettingsRequest.getCode() == DTCControlMode.DTC_OFF.getCode();
            response = new UDSControlDTCSettingsResponse(controlDTCSettingsRequest.getCode());
        } else if (request instanceof UDSDefineDataIdentifierRequest defineDataIdentifierRequest) {
            DynamicallyDefineSubFunction function =
                    Flag.find(DynamicallyDefineSubFunction.class, defineDataIdentifierRequest.getFunction())
                            .orElseThrow();

            int did = defineDataIdentifierRequest.getDid() & 0xFFFF;

            switch (function) {
                case CLEAR -> {
                    dids.remove(did);
                    response = new UDSDefineDataIdentifierResponse(function.getCode(), did);
                }
                case DynamicallyDefineSubFunction.DEFINE_BY_ADDRESS -> {
                    if (dids.containsKey(did)) {
                        return error(request, NegativeResponseCode.CONDITIONS_NOT_CORRECT);
                    }

                    List<DynamicallyDefinedDID> dids = new ArrayList<>();
                    BitReader reader = defineDataIdentifierRequest.bitReader();

                    int sizeLength = (int) reader.read(4);
                    int addressLength = (int) reader.read(4);

                    if (sizeLength != 1) {
                        return error(request, NegativeResponseCode.INVALID_MESSAGE_LEN_OR_FORMAT);
                    }

                    if (addressLength != 4) {
                        return error(request, NegativeResponseCode.INVALID_MESSAGE_LEN_OR_FORMAT);
                    }

                    while (reader.hasData()) {
                        long address = reader.readInt() & 0xFFFFFFFFL;
                        int length = reader.readByte() & 0xFF;

                        dids.add(new DynamicallyDefinedDID(did, address, length));

                        if (dids.size() > 10) {
                            return error(request, NegativeResponseCode.REQUEST_OUT_OF_RANGE);
                        }
                    }

                    this.dids.put(did, dids);
                    response = new UDSDefineDataIdentifierResponse(function.getCode(), did);
                }
                default -> {
                    return error(request, NegativeResponseCode.SERVICE_NOT_SUPPORTED);
                }
            }
        } else if (request instanceof UDSReadDataByIDRequest readDataByID) {
            int did = readDataByID.getDids()[0] & 0xFFFF;
            List<DynamicallyDefinedDID> definedDIDS = dids.get(did);
            if (definedDIDS == null) {
                return error(request, NegativeResponseCode.REQUEST_OUT_OF_RANGE);
            }

            ByteArrayOutputStream baos = new ByteArrayOutputStream();

            for (DynamicallyDefinedDID dyn : definedDIDS) {
                baos.write(dyn.getValue());
            }

            response = new UDSReadDataByIDResponse(did, baos.toByteArray());
        }

        return response;
    }

    private UDSResponse handleEngine2(UDSBody request) {
        UDSResponse response = null;

        if (request instanceof SubaruStatus1Request status1Request) {
            switch (status1Request.getCodes()[0]) {
                case 0x0C: // Ping
                    response = new SubaruStatus1Response(0x0C, new byte[2]);
                    break;
            }
        } else if (request instanceof SubaruVendorInfoRequest vendorInfoRequest) {
            SubaruVendorInfoResponse vendorInfoResponse = new SubaruVendorInfoResponse();

            Arrays.stream(vendorInfoRequest.getCodes()).forEach(code -> {
                SubaruVendorInfoRecord record = SubaruVendorInfoRecord.find(code);
                if (record == SubaruVendorInfoRecord.CALIBRATION) {
                    vendorInfoResponse.set(SubaruVendorInfoRecord.CALIBRATION, calibration.getName());
                }
            });

            response = vendorInfoResponse;
        } else if (request instanceof UDSDiagSessionControlRequest sessionControlRequest) {
            response = new UDSDiagSessionControlResponse(sessionControlRequest.getSessionType(), 0, 0);
        } else if (request instanceof UDSCommunicationControlRequest communicationControlRequest) {
            commControlDisabled = communicationControlRequest.getSubFunction() == 0x03 &&
                    communicationControlRequest.getCommunicationType() == 0x01;
            response = new UDSCommunicationControlResponse(communicationControlRequest.getCommunicationType());
        }

        return response;
    }

    private UDSResponse handleBodyControl(UDSBody request) {
        UDSResponse response = null;

        if (request instanceof UDSDiagSessionControlRequest sessionControlRequest) {
            response = new UDSDiagSessionControlResponse(sessionControlRequest.getSessionType(), 0, 0);
        } else if (request instanceof UDSCommunicationControlRequest communicationControlRequest) {
            response = new UDSCommunicationControlResponse(((UDSCommunicationControlRequest) request)
                    .getCommunicationType(), new byte[0]);
        }

        return response;
    }

    public synchronized Thread start() {
        if (thread == null || !thread.isAlive()) {
            thread = new Thread(this, getClass().getSimpleName());
            thread.setDaemon(true);

            running = true;
            thread.start();
        }

        return thread;
    }

    public void setCalibration(Calibration calibration) {
        this.calibration = calibration;
    }

    private class UDSSessionState {
        private DiagnosticSessionType sessionType = DiagnosticSessionType.DEFAULT_SESSION;
        private long testerLastSeen = System.currentTimeMillis();
        private int securityLevel = 0;

        public DiagnosticSessionType getSessionType() {
            if (System.currentTimeMillis() - testerLastSeen >= 3000L) {
                setSessionType(DiagnosticSessionType.DEFAULT_SESSION);
                setSecurityLevel(0);
            }

            return sessionType;
        }

        public void setSessionType(DiagnosticSessionType sessionType) {
            this.sessionType = sessionType;
            testerPresent();
        }

        public long getTesterLastSeen() {
            return testerLastSeen;
        }

        public void setTesterLastSeen(long testerLastSeen) {
            this.testerLastSeen = testerLastSeen;
        }

        public void testerPresent() {
            this.testerLastSeen = System.currentTimeMillis();
        }

        public int getSecurityLevel() {
            return securityLevel;
        }

        public void setSecurityLevel(int securityLevel) {
            this.securityLevel = securityLevel;
        }
    }

    private class Packet {
        private final CANArbitrationId address;
        private final BasicFrame frame;

        private Packet(CANArbitrationId address, BasicFrame frame) {
            this.address = address;
            this.frame = frame;
        }

        public ISOTPFrame toISOTPFrame() {
            return new ISOTPFrame(address, frame.getData());
        }

        public UDSFrame toUDSFrame() throws IOException {
            return UDSFrameReader.convert(protocol, frame);
        }
    }

    public class VirtualISOTPDevice implements ISOTPDevice, FrameReader<ISOTPFrame>, FrameWriter<BasicFrame> {
        @Override
        public FrameReader<ISOTPFrame> reader() {
            return this;
        }

        @Override
        public FrameWriter<BasicFrame> writer() {
            return this;
        }

        @Override
        public void close() throws IOException {
            SubaruDIVirtualECU.this.close();
        }

        /**
         * Called when the client-side wants to read a frame from the virtual ECU. This is a blocking method.
         * @return ISOTPFrame to return to the caller.
         * @throws IOException if there is an exception reading a frame
         */
        @Override
        public ISOTPFrame read() throws IOException {
            Packet packet;
            try {
                packet = ecuToTester.take();
            } catch (InterruptedException e) {
                throw new IOException(e);
            }

            return packet.toISOTPFrame();
        }

        @Override
        public void write(Address address, BasicFrame frame) throws IOException {
            testerToEcu.add(new Packet((CANArbitrationId) address, frame));
        }
    }

    private void close() {
        running = false;
        thread.interrupt();
    }

    public class VirtualJ2534Device implements J2534Device {
        @Override
        public CANDevice openCAN(CANFilter... filters) throws IOException {
            throw new UnsupportedOperationException();
        }

        @Override
        public ISOTPDevice openISOTOP(ISOTPFilter... filters) throws IOException {
            start();
            return new VirtualISOTPDevice();
        }

        @Override
        public void setConfig(int protocol, int parameter, int value) throws IOException {

        }

        @Override
        public int getConfig(int protocol, int parameter) throws IOException {
            return 0;
        }

        @Override
        public void close() throws IOException {

        }
    }

    public class DeviceDescriptor implements J2534DeviceDescriptor {
        @Override
        public J2534Device createDevice(Project project) throws IOException {
            if (project != null) {
                setProject(project);
            }
            return new VirtualJ2534Device();
        }

        public SubaruDIPlatform getPlatform() {
            return platform;
        }

        @Override
        public boolean equals(Object obj) {
            return obj instanceof DeviceDescriptor d && d.getPlatform() == getPlatform();
        }

        @Override
        public String toString() {
            return getPlatform().getVehicle().toString();
        }
    }

    private class DynamicallyDefinedDID {
        private final long declaredStart = System.currentTimeMillis();
        private final int did;
        private final long address;
        private final int length;

        private DynamicallyDefinedDID(int did, long address, int length) {
            this.did = did;
            this.address = address;
            this.length = length;
        }

        public long getAddress() {
            return address;
        }

        public int getLength() {
            return length;
        }

        public int getDid() {
            return did;
        }

        public byte[] getValue() {
            byte[] b = new byte[length];
            double d = Math.sin((double)(getAddress() + (System.currentTimeMillis() - declaredStart)) / 1000d);
            b[0] = (byte) (d * 0xFF);
            return b;
        }
    }
}
