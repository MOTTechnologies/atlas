package com.github.manevolent.atlas.connection.subaru;

import com.github.manevolent.atlas.BitWriter;
import com.github.manevolent.atlas.connection.*;
import com.github.manevolent.atlas.logging.Log;
import com.github.manevolent.atlas.model.*;
import com.github.manevolent.atlas.model.crypto.MemoryEncryption;
import com.github.manevolent.atlas.model.crypto.MemoryEncryptionType;
import com.github.manevolent.atlas.model.crypto.SubaruDIChecksum;
import com.github.manevolent.atlas.model.uds.SecurityAccessProperty;
import com.github.manevolent.atlas.protocol.isotp.ISOTPFrameReader;
import com.github.manevolent.atlas.protocol.isotp.ISOTPSpyDevice;
import com.github.manevolent.atlas.protocol.j2534.*;
import com.github.manevolent.atlas.protocol.subaru.SubaruProtocols;
import com.github.manevolent.atlas.protocol.subaru.SubaruSecurityAccessCommandAES;
import com.github.manevolent.atlas.protocol.subaru.uds.SubaruVendorInfoRecord;
import com.github.manevolent.atlas.protocol.subaru.uds.request.SubaruStatus1Request;
import com.github.manevolent.atlas.protocol.subaru.uds.request.SubaruVendorInfoRequest;
import com.github.manevolent.atlas.protocol.subaru.uds.response.SubaruVendorInfoResponse;
import com.github.manevolent.atlas.protocol.uds.*;
import com.github.manevolent.atlas.protocol.uds.command.UDSReadActiveDiagnosticSession;
import com.github.manevolent.atlas.protocol.uds.flag.*;
import com.github.manevolent.atlas.protocol.uds.request.*;
import com.github.manevolent.atlas.protocol.uds.response.*;
import com.github.manevolent.atlas.ui.behavior.ProgressListener;
import com.github.manevolent.atlas.ui.util.Errors;
import com.google.common.collect.Sets;
import org.checkerframework.checker.units.qual.C;

import java.io.*;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.concurrent.TimeoutException;
import java.util.function.Supplier;
import java.util.logging.Level;

import static com.github.manevolent.atlas.protocol.subaru.SubaruDITComponent.*;
import static com.github.manevolent.atlas.protocol.subaru.SubaruDITComponent.CENTRAL_GATEWAY;
import static com.github.manevolent.atlas.protocol.uds.flag.CommunicationControlSubFunction.DISABLE_RX_AND_TX;
import static com.github.manevolent.atlas.protocol.uds.flag.CommunicationControlType.NETWORK_MANAGEMENT;
import static com.github.manevolent.atlas.protocol.uds.flag.DTCControlMode.DTC_OFF;

public class SubaruDIConnection extends UDSConnection {
    private static final String securityAccessPropertyFormat = "subaru.dit.securityaccess.%s";
    public static final String gatewayKeyProperty = String.format(securityAccessPropertyFormat, "gateway");
    public static final String memoryReadKeyProperty = String.format(securityAccessPropertyFormat, "memory_read");
    public static final String memoryWriteKeyProperty = String.format(securityAccessPropertyFormat, "memory_write");
    public static final String flashWriteKeyProperty = String.format(securityAccessPropertyFormat, "flash_write");
    public static final String datalogKeyProperty = String.format(securityAccessPropertyFormat, "datalog");

    private static final Set<ConnectionFeature> supportedFeatures = Collections.unmodifiableSet(
            Sets.newHashSet(Arrays.asList(
                    ConnectionFeature.SPY,
                    ConnectionFeature.FLASH_ROM,
                    ConnectionFeature.DATALOG,
                    ConnectionFeature.READ_MEMORY)));

    private static final UDSProtocol protocol = SubaruProtocols.DIT;

    private final UDSComponent[] components = {
            CENTRAL_GATEWAY,
            ENGINE_1,
            ENGINE_2,
            TRANSMISSION,
            UNKNOWN_1,
            UNKNOWN_2,
            UNKNOWN_3,
            UNKNOWN_4,
            UNKNOWN_5,
            UNKNOWN_6
    };

    private boolean flashing = false;
    private Platform lastIdentifiedPlatform;

    /**
     * ECU orders things in non-native order
     * @param array array to reverse
     */
    private static void reverse(byte[] array) {
        for (int i = 0; i < array.length / 2; i++) {
            byte temp = array[i];
            array[i] = array[array.length - 1 - i];
            array[array.length - 1 - i] = temp;
        }
    }

    public SubaruDIConnection(Supplier<J2534DeviceProvider<?>> provider) {
        super(provider);
    }

    @Override
    protected UDSComponent getECUComponent() {
        return ENGINE_1;
    }

    @Override
    protected UDSSession newSession(SessionType type) throws IOException, TimeoutException, InterruptedException {
        J2534Device device = findDevice();
        if (device == null) {
            throw new NullPointerException("No J2534 device found");
        }

        AsyncUDSSession session;

        if (type == SessionType.NORMAL) {
            ISOTPDevice isotpDevice = device.openISOTOP(components);

            device.setConfig(J2534Protocol.ISO15765, J2534Parameter.LOOPBACK, 0);
            device.setConfig(J2534Protocol.ISO15765, J2534Parameter.ISO15765_BS, 0);
            device.setConfig(J2534Protocol.ISO15765, J2534Parameter.ISO15765_STMIN, 0);
            device.setConfig(J2534Protocol.ISO15765, J2534Parameter.BS_TX, 0xffff);
            device.setConfig(J2534Protocol.ISO15765, J2534Parameter.STMIN_TX, 0xffff);
            device.setConfig(J2534Protocol.ISO15765, J2534Parameter.ISO15765_WFT_MAX, 0);

            session = new AsyncUDSSession(isotpDevice, protocol);
        } else if (type == SessionType.SPY) {
            ISOTPFrameReader isotpReader = new ISOTPFrameReader(device.openCAN().reader());
            ISOTPSpyDevice spyDevice = new ISOTPSpyDevice(device, isotpReader);
            session = new AsyncUDSSession(spyDevice, protocol);
        } else {
            throw new UnsupportedEncodingException();
        }

        return session;
    }

    @Override
    public int getMaximumReadSize() {
        return 0x32;
    }

    @Override
    public byte[] readMemory(MemoryAddress address, Variant variant, int length)
            throws IOException, TimeoutException, InterruptedException {
        long offset = address.getOffset(variant);
        int maxReadSize = getMaximumReadSize();

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        BitWriter bitWriter = new BitWriter(baos);
        bitWriter.write(0x14);
        bitWriter.writeInt((int) (offset & 0xFFFFFFFFL));
        bitWriter.write((byte) Math.min(0xFF, length));

        AsyncUDSSession session = (AsyncUDSSession) getSession();
        try (UDSTransaction<UDSReadMemoryByAddressRequest, UDSReadMemoryByAddressResponse>
                     transaction = session.request(getECUComponent().getSendAddress(),
                new UDSReadMemoryByAddressRequest(4, offset, 1, length))) {
            byte[] data = transaction.get().getData();
            //reverse(data);
            return data;
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    @Override
    public Platform identify() throws IOException, TimeoutException, InterruptedException, UnknownPlatformException {
        AsyncUDSSession session;
        try {
            session = (AsyncUDSSession) getSession();
        } catch (Exception e) {
            throw new IOException("Failed to obtain active session", e);
        }

        SubaruVendorInfoResponse response;
        try {
            response = session.request(ENGINE_2, new SubaruVendorInfoRequest(SubaruVendorInfoRecord.CALIBRATION));
        } catch (TimeoutException ex) {
            if (lastIdentifiedPlatform != null) {
                return lastIdentifiedPlatform;
            } else {
                throw ex;
            }
        }

        String calibration = response.getAsString(SubaruVendorInfoRecord.CALIBRATION);
        Platform platform = (lastIdentifiedPlatform = SubaruDIPlatform.find(calibration));

        if (platform == null) {
            throw new UnknownPlatformException("Unrecognized calibration: \"" + calibration + "\".");
        }

        return platform;
    }

    private FlashResult writeCalibrationIntl(UDSSession session, SubaruDIPlatform diPlatform, Calibration calibration,
                                             ProgressListener progressListener) throws FlashException {

        progressListener.updateProgress("Connecting to vehicle...", 0f);

        try {
            changeConnectionMode(ConnectionFeature.FLASH_ROM);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (TimeoutException e) {
            throw new FlashException(FlashResult.State.CRITICAL_FAILURE, "Change connection mode failed", e);
        } catch (InterruptedException e) {
            throw new FlashException(FlashResult.State.CRITICAL_FAILURE, "Change connection mode timed out", e);
        }

        flashing = true;

        if (calibration.getSection().getBaseAddress() != diPlatform.getFlashStart()) {
            throw new FlashException(FlashResult.State.PREVENTED, "Calibration does not start at memory address " +
                    Integer.toHexString((int) (diPlatform.getFlashStart() & 0xFFFFFFFFL)) + ".");
        } else if (calibration.getSection().getEndAddress() != diPlatform.getFlashEnd()) {
            throw new FlashException(FlashResult.State.PREVENTED, "Calibration does not end at memory address " +
                    Integer.toHexString((int) (diPlatform.getFlashEnd() & 0xFFFFFFFFL)) + ".");
        } else if (calibration.getLength() != diPlatform.getFlashSize()) {
            throw new FlashException(FlashResult.State.PREVENTED, "Calibration data size (" +
                    calibration.getLength() + ") does not match" +
                    " expected size (" + diPlatform.getFlashSize() + ").");
        }

        MemoryEncryptionType type = calibration.getSection().getEncryptionType();
        if (type != MemoryEncryptionType.SUBARU_DIT) {
            throw new FlashException(FlashResult.State.PREVENTED, "Memory encryption is not supported: "
                    + type.toString() + ".");
        }

        MemoryEncryption encryption = type.getFactory().create();

        byte[] flashParameters;
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream(1 + 4 + 4);
            BitWriter fieldWriter = new BitWriter(baos);
            fieldWriter.writeNibble((byte) 4);
            fieldWriter.writeNibble((byte) 4);
            fieldWriter.writeInt((int) (diPlatform.getFlashStart() & 0xFFFFFFFFL));
            fieldWriter.writeInt((int) (diPlatform.getFlashSize() & 0xFFFFFFFFL));
            flashParameters = baos.toByteArray();
        } catch (IOException ex) {
            throw new FlashException(FlashResult.State.PREVENTED, "Failed to prepare flash parameters", ex);
        }

        try {
            keepAliveIntl();
        } catch (Exception ex) {
            throw new FlashException(FlashResult.State.PREVENTED, "Tester present failed", ex);
        }

        progressListener.updateProgress("Waiting for ECU reboot...", 0.00f);

        try {
            Thread.sleep(2000L);
        } catch (InterruptedException e) {
            throw new FlashException(FlashResult.State.PREVENTED, "Interrupted before recalibration began", e);
        }

        progressListener.updateProgress("Clearing flash...", 0.05f);

        // Clear flash
        UDSRoutineControlResponse clearFlashResponse;
        try {
            clearFlashResponse = session.request(ENGINE_1,
                    new UDSRoutineControlRequest(
                            RoutineControlSubFunction.START_ROUTINE,
                            0xFF00,
                            flashParameters
                    ),
                    30_000);
        } catch (UDSNegativeResponseException negative) {
            NegativeResponseCode code = negative.getResponse().getResponseCode();
            if (code == NegativeResponseCode.CONDITIONS_NOT_CORRECT ||
                    code == NegativeResponseCode.SERVICE_NOT_SUPPORTED ||
                    code == NegativeResponseCode.SERVICE_NOT_SUPPORTED_IN_SESSION ||
                    code == NegativeResponseCode.INVALID_MESSAGE_LEN_OR_FORMAT) {
                throw new FlashException(FlashResult.State.REJECTED, "Clear flash rejected", negative);
            } else {
                throw new FlashException(FlashResult.State.CRITICAL_FAILURE, "Clear flash failed", negative);
            }
        } catch (IOException e) {
            throw new FlashException(FlashResult.State.CRITICAL_FAILURE, "Clear flash failed", e);
        } catch (TimeoutException e) {
            throw new FlashException(FlashResult.State.CRITICAL_FAILURE, "Clear flash timed out", e);
        } catch (InterruptedException e) {
            throw new FlashException(FlashResult.State.CRITICAL_FAILURE, "Interrupted during flash clear", e);
        }

        try {
            keepAlive();
        } catch (Exception e) {
            // Ignore
            Log.can().log(Level.WARNING, "Problem sending keep-alive before download request", e);
        }

        try {
            progressListener.updateProgress("Starting upload...", 0.10f);
        } catch (Exception e) {
            Log.can().log(Level.WARNING, "Problem sending progress update", e);
        }

        UDSDownloadResponse downloadResponse;
        try {
            downloadResponse = session.request(ENGINE_1,
                    new UDSDownloadRequest(
                            0x0, // No compression
                            0x4, // Encrypted (Feistel)
                            0x0, // Memory identifier
                            4, diPlatform.getFlashStart(),
                            4, diPlatform.getFlashSize()
                    ),
                    10_000);
        } catch (IOException e) {
            throw new FlashException(FlashResult.State.CRITICAL_FAILURE, "Download request failed", e);
        } catch (TimeoutException e) {
            throw new FlashException(FlashResult.State.CRITICAL_FAILURE, "Download request timed out", e);
        } catch (InterruptedException e) {
            throw new FlashException(FlashResult.State.CRITICAL_FAILURE, "Interrupted during download request", e);
        }

        // Subtract "6" here because protocol overhead is about 6 bytes
        int blockSize = (int) downloadResponse.getBlockLength() - 6;
        if (blockSize <= 0) {
            throw new FlashException(FlashResult.State.CRITICAL_FAILURE, "Received bad block size " + blockSize);
        }

        byte[] buffer = new byte[blockSize];
        int transferIndex = 0;
        UDSTransferResponse transferResponse;
        long written = 0;
        for (long offs = diPlatform.getFlashStart(); offs < diPlatform.getFlashEnd(); offs += blockSize) {
            try {
                float progress = (float)written / diPlatform.getFlashSize();
                progress = progress * 0.9f;
                progress += 0.1f;
                progressListener.updateProgress("Uploading calibration data to ECU...", progress);
            } catch (Exception e) {
                Log.can().log(Level.WARNING, "Problem sending progress update", e);
            }

            transferIndex += 1;
            if (transferIndex > 0xFF) {
                transferIndex = 0;
            }

            int blockSendSize = (int) Math.min(diPlatform.getFlashEnd() - offs, blockSize);

            try {
                // Read the decrypted data from the calibration file
                calibration.read(buffer, offs, 0, blockSendSize);

                byte[] send = new byte[blockSendSize];
                System.arraycopy(buffer, 0, send, 0, blockSendSize);

                // Encrypt the data before sending it
                encryption.encrypt(calibration, send, 0, blockSendSize);

                int maxTries = 5;
                for (int i = 0; i < maxTries; i ++) {
                    try {
                        try {
                            keepAliveIntl();
                        } catch (Exception e) {
                            // Ignore
                            Log.can().log(Level.WARNING, "Problem sending keep-alive during calibration data transfer", e);
                        }

                        session.request(ENGINE_1, new UDSTransferRequest(transferIndex, offs, send), 1000);
                        break;
                    } catch (TimeoutException ex) {
                        if (i == maxTries - 1) {
                            throw ex;
                        } else {
                            Log.can().log(Level.WARNING, "Timed out sending calibration data to ECU", ex);
                        }
                    }
                }
            } catch (IOException e) {
                throw new FlashException(FlashResult.State.CRITICAL_FAILURE, "Write flash failed", e);
            } catch (TimeoutException e) {
                throw new FlashException(FlashResult.State.CRITICAL_FAILURE, "Write flash timed out", e);
            } catch (InterruptedException e) {
                throw new FlashException(FlashResult.State.CRITICAL_FAILURE, "Interrupted during flash write", e);
            }

            written += blockSendSize;
        }

        try {
            progressListener.updateProgress("Finishing upload...", 1f);
        } catch (Exception e) {
            Log.can().log(Level.WARNING, "Problem sending progress update", e);
        }

        UDSTransferExitResponse transferExitResponse;
        try {
            keepAliveIntl();
            transferExitResponse = session.request(ENGINE_1, new UDSTransferExitRequest(), 30_000);
        } catch (IOException e) {
            throw new FlashException(FlashResult.State.CRITICAL_FAILURE, "Transfer exit failed", e);
        } catch (TimeoutException e) {
            throw new FlashException(FlashResult.State.CRITICAL_FAILURE, "Transfer exit timed out", e);
        } catch (InterruptedException e) {
            throw new FlashException(FlashResult.State.CRITICAL_FAILURE, "Interrupted during transfer exit", e);
        }

        try {
            progressListener.updateProgress("Verifying uploaded calibration...", 1f);
        } catch (Exception e) {
            Log.can().log(Level.WARNING, "Problem sending progress update", e);
        }

        // Check flash (checksum)
        UDSRoutineControlResponse checkFlashResponse;
        try {
            keepAliveIntl();
            // THIS IS INCREDIBLY IMPORTANT! DO NOT send 0xFF00 here; it will clear flash again
            checkFlashResponse = session.request(ENGINE_1,
                    new UDSRoutineControlRequest(RoutineControlSubFunction.START_ROUTINE.getCode(), 0xFF01,
                            flashParameters), 30_000);
        } catch (IOException e) {
            throw new FlashException(FlashResult.State.CRITICAL_FAILURE, "Check flash failed", e);
        } catch (TimeoutException e) {
            throw new FlashException(FlashResult.State.CRITICAL_FAILURE, "Check flash timed out", e);
        } catch (InterruptedException e) {
            throw new FlashException(FlashResult.State.CRITICAL_FAILURE, "Interrupted during flash check", e);
        }

        if (checkFlashResponse.getData()[0] != 0x1) {
            throw new FlashException(FlashResult.State.FAILED, "ECU checksum verification failed");
        }

        try {
            progressListener.updateProgress("Recalibration complete", 1f);
        } catch (Exception e) {
            Log.can().log(Level.WARNING, "Problem sending progress update", e);
        }

        return new FlashResult(FlashResult.State.SUCCESS, (int) written);
    }

    @Override
    public FlashResult writeCalibration(Platform platform, Calibration calibration, ProgressListener progressListener)
            throws FlashException {
        if (!(platform instanceof SubaruDIPlatform diPlatform)) {
            throw new FlashException(FlashResult.State.UNSUPPORTED,
                    "Platform is not a Subaru Direct Injection platform");
        }

        UDSSession session;
        try {
            session = getSession();
        } catch (Exception e) {
            throw new FlashException(FlashResult.State.PREVENTED, "Failed to obtain active session", e);
        }

        progressListener.updateProgress("Verifying calibration...", 0f);

        Checksum checksum = platform.getChecksum(calibration);
        try {
            if (!checksum.validate(calibration)) {
                throw new FlashException(FlashResult.State.PREVENTED, "Calibration checksum is invalid.");
            }
        } catch (IOException e) {
            throw new FlashException(FlashResult.State.PREVENTED, "Calibration checksum calculation failed.", e);
        }

        try {
            return writeCalibrationIntl(session, diPlatform, calibration, progressListener);
        } finally {
            flashing = false;
        }
    }

    @Override
    public Calibration readCalibration(Platform platform, ProgressListener progressListener)
            throws IOException, TimeoutException, InterruptedException {
       throw new UnsupportedOperationException();
    }

    @Override
    protected void change(ConnectionMode newMode) throws IOException, TimeoutException, InterruptedException {
        ConnectionMode oldMode = getConnectionMode();

        if (newMode == ConnectionMode.DISCONNECTED) {
            setSession(null);
            return;
        }

        Project project = getProject();
        if (project == null) {
            throw new IllegalStateException("Project is not set");
        }

        if (oldMode == newMode) {
            return;
        }

        UDSSession session = getSession();

        if (flashing) {
            throw new IllegalStateException("ECU is currently re-calibrating");
        }

        // Ping the system to ensure we are connected
        TimeoutException ex_last = null;
        for (int i = 0; i < 3; i ++) {
            try {
                session.request(ENGINE_2, new SubaruStatus1Request(0x0C), 1000L);
                ex_last = null;
                break;
            } catch (TimeoutException ex) {
                ex_last = ex;
            }
        }

        if (ex_last != null) {
            throw ex_last;
        }

        if (newMode == ConnectionMode.IDLE) {
            // If we're idle, exit now
            return;
        }

        // Select AES key for the gateway
        SecurityAccessProperty cgwAccessProperty;
        cgwAccessProperty = project.getActiveKeySet().getProperty(gatewayKeyProperty, SecurityAccessProperty.class);

        // Set AES key for the ECU
        String propertyName;
        switch (newMode) {
            case READ_MEMORY -> propertyName = memoryReadKeyProperty;
            case WRITE_MEMORY -> propertyName = memoryWriteKeyProperty;
            case FLASH_ROM -> propertyName = flashWriteKeyProperty;
            case DATALOG -> propertyName = datalogKeyProperty;
            default -> throw new UnsupportedOperationException(newMode.name());
        }

        SecurityAccessProperty engineAccessProperty;
        engineAccessProperty = project.getActiveKeySet().getProperty(propertyName, SecurityAccessProperty.class);
        if (engineAccessProperty != null && engineAccessProperty.getLevel() != 0
                && engineAccessProperty.getKey().length != 16) {
            throw new IllegalArgumentException("Engine access key for " + newMode + " is not 16 bytes long.");
        }

        long minResponseTime, maxResponseTime;

        if (newMode == ConnectionMode.FLASH_ROM) {
            session.request(ENGINE_1, new UDSDiagSessionControlRequest(DiagnosticSessionType.EXTENDED_SESSION));

            // Change to an extended session request with all devices on the bus,
            // and once we hear back from the gateway, sleep for the minimum response time.
            // This extended session broadcast is required in the UDS reprogramming spec.
            session.request(BROADCAST,
                    new UDSDiagSessionControlRequest(DiagnosticSessionType.EXTENDED_SESSION),
                    ENGINE_2, CENTRAL_GATEWAY);
        } else {
            // Otherwise, just change to an extended session with the gateway only
            UDSDiagSessionControlResponse sessionControlResponse = session.request(CENTRAL_GATEWAY,
                    new UDSDiagSessionControlRequest(DiagnosticSessionType.EXTENDED_SESSION));
        }

        if (cgwAccessProperty != null && cgwAccessProperty.getLevel() != 0 && engineAccessProperty != null &&
            engineAccessProperty.getLevel() != 0) {
            if (cgwAccessProperty.getKey().length != 16) {
                throw new IllegalArgumentException("Gateway access key is not 16 bytes long.");
            }

            // Use the CGW AES key
            new SubaruSecurityAccessCommandAES(
                    cgwAccessProperty.getLevel(),
                    CENTRAL_GATEWAY,
                    cgwAccessProperty.getKey()
            ).execute(session);

            // Instruct CGW to allow communication to ECU
            session.request(
                    CENTRAL_GATEWAY,
                    new UDSRoutineControlRequest(RoutineControlSubFunction.START_ROUTINE, 0x0200)
            );
        }

        // If we are flashing, disable non-critical CAN communications
        // See: https://cdn.vector.com/cms/content/products/Flash_Bootloader/Docs/Vector_Flash_Bootloader_Technical_Reference.pdf
        if (newMode == ConnectionMode.FLASH_ROM) {
            session.send(BROADCAST, new UDSTesterPresentRequest(0x80));
            session.request(BROADCAST, new UDSControlDTCSettingsRequest(DTC_OFF));

            // 0x03 - Disable RX and TX
            // 0x01 - ... of normal communications
            session.send(BROADCAST, new UDSTesterPresentRequest(0x80));
            session.request(BROADCAST, new UDSCommunicationControlRequest(DISABLE_RX_AND_TX, NETWORK_MANAGEMENT));

            // Instruct CGW to allow communication to ECU
            session.request(BROADCAST, new UDSTesterPresentRequest(0x80));
            try {
                session.request(
                        CENTRAL_GATEWAY,
                        new UDSRoutineControlRequest(RoutineControlSubFunction.START_ROUTINE, 0x0201)
                );
            } catch (Exception ex) {
                // Ignore
                Log.can().log(Level.WARNING, "Ignoring CGW command; proceeding with mode change", ex);
            }
        }

        session.send(ENGINE_1, new UDSDiagSessionControlRequest(DiagnosticSessionType.EXTENDED_SESSION));

        // Use the engine AES key to hop over to whatever security level we are looking for
        // If this fails, we have the wrong key
        if (engineAccessProperty != null && engineAccessProperty.getLevel() != 0) {
            new SubaruSecurityAccessCommandAES(
                    engineAccessProperty.getLevel(),
                    ENGINE_1,
                    engineAccessProperty.getKey()
            ).execute(session);
        }

        // If we need to enter a programming session...
        if (newMode == ConnectionMode.FLASH_ROM) {
            // CONDITIONS_NOT_CORRECT:
            // This can fail if the vehicle is in motion or the engine is running (RPM > 0 || vehicle speed > 0)
            // or perhaps if the battery voltage is too low
            try {
                session.request(ENGINE_1, new UDSDiagSessionControlRequest(DiagnosticSessionType.PROGRAMMING_SESSION),
                        2500L);
            } catch (Exception ex) {
                try {
                    session.request(ENGINE_1, new UDSDiagSessionControlRequest(0x4),
                        2500L);
                } catch (Exception ex2) {
                    ex2.addSuppressed(ex);
                    throw ex2;
                }
            }
        }
    }

    @Override
    protected int getNextDataIdentifierSize(List<MemoryParameter> parameters) {
        return 10;
    }

    /**
     * This method is separated as the programming session still needs to send keep-alive
     */
    @SuppressWarnings("resource")
    private boolean keepAliveIntl() throws IOException, InterruptedException, TimeoutException {
        UDSSession session = getSession();
        if (getConnectionMode() == ConnectionMode.IDLE || getConnectionMode() == ConnectionMode.DATALOG) {
            session.request(ENGINE_2, new SubaruStatus1Request(0x0C));
        } else {
            // The active diagnostic session will probably be an extended session, so broadcast tester present
            session.request(BROADCAST, new UDSTesterPresentRequest(new byte[] { (byte) 0x80 }));
        }
        return true;
    }

    @Override
    protected boolean keepAlive() throws IOException, TimeoutException, InterruptedException {
        ConnectionMode connectionMode = getConnectionMode();

        if (connectionMode == ConnectionMode.DISCONNECTED || flashing || isConnectionModeChanging()) {
            // This doesn't need tester present
            return false;
        }

        return keepAliveIntl();
    }

    @Override
    protected UDSProtocol getProtocol() {
        return SubaruProtocols.DIT;
    }

    @Override
    public List<Platform> getPlatforms() {
        return Arrays.asList(SubaruDIPlatform.values());
    }

    @Override
    public ConnectionType getType() {
        return ConnectionType.SUBARU_DI;
    }

    @Override
    public Set<ConnectionFeature> getFeatures() {
        return supportedFeatures;
    }

    @Override
    public void setParameters(Variant variant, Set<MemoryParameter> parameters)
            throws IOException, InterruptedException, TimeoutException {
        if (flashing) {
            throw new IllegalStateException("cannot set parameters while flashing");
        }

        super.setParameters(variant, parameters);
    }

    public static class Factory implements ConnectionFactory {
        @Override
        public Connection createConnection(Supplier<J2534DeviceProvider<?>> provider) {
            return new SubaruDIConnection(provider);
        }

        @Override
        public List<PropertyDefinition> getPropertyDefinitions() {
            return Arrays.asList(
                    new PropertyDefinition(true, gatewayKeyProperty,
                            "Gateway Access Key",
                            "The security access configuration for disarming the central gateway module",
                            SecurityAccessProperty.class),
                    new PropertyDefinition(true, memoryReadKeyProperty,
                            "Memory Read Key",
                            "The security access configuration for placing the ECU into memory read mode",
                            SecurityAccessProperty.class),
                    new PropertyDefinition(true, memoryWriteKeyProperty,
                            "Memory Write Key",
                            "The security access configuration for placing the ECU into memory write mode",
                            SecurityAccessProperty.class),
                    new PropertyDefinition(true, flashWriteKeyProperty,
                            "Flash Write Key",
                            "The security access configuration for placing the ECU into programming mode",
                            SecurityAccessProperty.class),
                    new PropertyDefinition(true, datalogKeyProperty,
                            "Datalog Key",
                            "The security access configuration for placing the ECU into a datalog session",
                            SecurityAccessProperty.class)
            );
        }

        @Override
        public Set<ConnectionFeature> getSupportedFeatures() {
            return supportedFeatures;
        }
    }
}
