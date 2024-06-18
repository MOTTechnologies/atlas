package com.github.manevolent.atlas.connection;

import com.github.manevolent.atlas.BitReader;
import com.github.manevolent.atlas.Frame;
import com.github.manevolent.atlas.logging.Log;

import com.github.manevolent.atlas.model.MemoryParameter;
import com.github.manevolent.atlas.model.Project;
import com.github.manevolent.atlas.model.Variant;
import com.github.manevolent.atlas.protocol.j2534.DeviceNotFoundException;
import com.github.manevolent.atlas.protocol.j2534.J2534Device;
import com.github.manevolent.atlas.protocol.j2534.J2534DeviceDescriptor;
import com.github.manevolent.atlas.protocol.j2534.J2534DeviceProvider;
import com.github.manevolent.atlas.protocol.uds.*;
import com.github.manevolent.atlas.protocol.uds.flag.DataIdentifier;
import com.github.manevolent.atlas.protocol.uds.flag.DynamicallyDefineSubFunction;
import com.github.manevolent.atlas.protocol.uds.flag.ECUResetMode;
import com.github.manevolent.atlas.protocol.uds.request.*;
import com.github.manevolent.atlas.protocol.uds.response.UDSDefineDataIdentifierResponse;
import com.github.manevolent.atlas.protocol.uds.response.UDSReadDTCResponse;
import com.github.manevolent.atlas.protocol.uds.response.UDSReadDataByIDResponse;
import com.github.manevolent.atlas.ui.util.Jobs;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import java.util.logging.Level;
import java.util.stream.Collectors;

import static org.apache.commons.lang.ArrayUtils.reverse;

public abstract class UDSConnection extends AbstractConnection<UDSConnectionListener> {
    private final Supplier<J2534DeviceProvider<?>> deviceProvider;

    private ConnectionMode connectionMode = ConnectionMode.DISCONNECTED;

    private UDSSession session;
    private SessionType sessionType;

    private Project project;

    private KeepAliveThread keepAliveThread ;
    private final Object stateObject = new Object();
    private final Object parameterLock = new Object();
    private long lastFrameRead = 0L;
    private long lastFrameSent = 0L;

    /**
     * The active, dynamically defined DIDs in the ECU
     */
    private final List<DynamicallyDefinedDID> definedDIDS = new CopyOnWriteArrayList<>();

    /**
     * A flag that indicates if the ECU's connection mode is actively changing.
     */
    private boolean changing;


    public UDSConnection(Supplier<J2534DeviceProvider<?>> deviceProvider) {
        this.deviceProvider = deviceProvider;
    }

    @Override
    public boolean isConnectionModeChanging() {
        return changing;
    }

    @Override
    public boolean isConnected() {
        return session != null && getConnectionMode() != ConnectionMode.DISCONNECTED;
    }

    @Override
    public ConnectionMode getConnectionMode() {
        return connectionMode;
    }

    /**
     * Finds a J2534 device using the system device provider (see: Devices class)
     * @return J2534 device identified by the current configuration.
     */
    protected J2534Device findDevice() throws IOException, TimeoutException, InterruptedException {
        AtomicReference<IOException> ioException = new AtomicReference<>();
        AtomicReference<J2534Device> device = new AtomicReference<>();
        J2534DeviceProvider<?> provider = deviceProvider.get();

        Thread thread = Jobs.fork(() -> {
            try {
                J2534DeviceDescriptor descriptor = provider.autoselectDevice();
                device.set(descriptor.createDevice(project));
            } catch (DeviceNotFoundException e) {
                ioException.set(new IOException(e));
            } catch (IOException e) {
                ioException.set(e);
            }
        });

        boolean completed = thread.join(Duration.of(3L, ChronoUnit.SECONDS));

        IOException e = ioException.get();
        if (e != null) {
            throw new IOException(e);
        }

        if (!completed) {
            // Do our best by interrupting the thread
            thread.interrupt();
            throw new TimeoutException("Timed out waiting to open a J2534 device" +
                    " using provider " + provider.getClass().getSimpleName() + ".");
        }

        J2534Device d = device.get();
        if (d != null) {
            fireEvent(listener -> listener.onDeviceFound(this, d));
            return d;
        } else {
            throw new NullPointerException("device");
        }
    }

    /**
     * Sets the active project for this connection.
     * @param project project instance.
     */
    public void setProject(Project project) {
        if (this.project != project) {
            fireEvent(listener -> listener.onProjectChanging(this, this.project, project));
            this.project = project;
            fireEvent(listener -> listener.onProjectChanged(this, project));
        }
    }

    /**
     * Gets the project associated with this connection.
     * @return project instance.
     */
    public Project getProject() {
        return project;
    }

    /**
     * Gets the time, in milliseconds, that the last frame was read over the wire.
     * @return time, in milliseconds.
     */
    public long getLastFrameRead() {
        return lastFrameRead;
    }

    /**
     * Gets the time, in milliseconds, that the last frame was sent over the wire.
     * @return time, in milliseconds.
     */
    public long getLastFrameSent() {
        return lastFrameSent;
    }

    protected void setLastFrameRead(long millis) {
        this.lastFrameRead = millis;
    }

    protected void setLastFrameSent(long millis) {
        this.lastFrameSent = millis;
    }

    /**
     * Gets the interval between keep-alive events, and the delay after any frame is sent where a keep-alive will first
     * be sent. This is intended to operate with "tester present" frames in UDS.
     *
     * @return milliseconds.
     */
    public long getKeepAliveInterval() {
        return 1000L;
    }

    /**
     * Gets the maximum amount of time to wait after a keep-alive message has failed to send. Defaults to the result
     * of getKeepAliveInterval().
     * @return wait time, in milliseconds.
     */
    protected long getFailedKeepAlivePause() {
        return getKeepAliveInterval();
    }

    /**
     * Sends a keep-alive message (i.e. tester present) to the receiving endpoint
     *
     * @return
     * @throws IOException      if there is a transport error when sending the keep-alive message
     * @throws TimeoutException if there is a protocol-level timeout sending the keep-alive message
     */
    protected abstract boolean keepAlive() throws IOException, TimeoutException, InterruptedException;

    /**
     * Gets the current UDS session, or creates one if no connection exists.
     * @return UDS session.
     */
    public UDSSession getSession() {
        return session;
    }

    /**
     * Internally sets the connection mode and fires a connection mode event to any listeners.
     * @param mode new mode.
     */
    protected void setConnectionMode(ConnectionMode mode) {
        if (this.connectionMode != mode) {
            ConnectionMode old = this.connectionMode;
            this.connectionMode = mode;

            changing = false;
            fireEvent(listener -> listener.onConnectionModeChanged(this, old, mode));
        }
    }

    /**
     * Gets the protocol associated with this connection.
     * @return protocol.
     */
    protected abstract UDSProtocol getProtocol();

    /**
     * Gets the ECU component that will be the destination for routines (memory read, etc.).
     * @return ECU component.
     */
    protected abstract UDSComponent getECUComponent();

    /**
     * Finds if the keep-alive thread should dispatch a keep-alive message by calling the keepAlive() method.
     * @param deadline the current deadline, by which a keep-alive message should be sent.
     * @return true if a keep-alive message should be sent, false otherwise.
     */
    protected boolean shouldSendKeepAlive(long deadline) {
        return System.currentTimeMillis() >= deadline;
    }

    @Override
    public SessionType getSessionType() {
        UDSSession session = getSession();
        return session != null ? sessionType : null;
    }

    @Override
    public void changeConnectionMode(SessionType sessionType, ConnectionMode newMode)
            throws IOException, TimeoutException, InterruptedException {
        ConnectionMode currentMode = connectionMode;
        if (newMode == currentMode) {
            return;
        }

        if (newMode == ConnectionMode.DATALOG) {
            clearDataIdentifiers();
        }

        if (!sessionType.supportsMode(newMode)) {
            throw new UnsupportedEncodingException(sessionType.name() + " does not support " + newMode);
        }

        if (currentMode != ConnectionMode.DISCONNECTED && getSessionType() != sessionType) {
            disconnect();
        }

        synchronized (stateObject) {
            try {
                changing = true;

                if (currentMode == ConnectionMode.DISCONNECTED && session == null) {
                    stateObject.notifyAll();
                    session = connect(sessionType);
                    this.sessionType = sessionType;
                } else if (newMode == ConnectionMode.DISCONNECTED) {
                    if (session != null) {
                        UDSSession session_closed = session;
                        Thread thread = Jobs.fork(() -> {
                            try {
                                session_closed.close();
                            } catch (IOException e) {
                                throw new RuntimeException(e);
                            }
                        });

                        thread.join(1000L);

                        session = null;
                    }

                    setConnectionMode(newMode);
                    stateObject.notifyAll();
                    return;
                }

                if (!isSpying() || newMode != ConnectionMode.IDLE) {
                    change(newMode);
                }

                if (!isSpying() && (keepAliveThread == null || !keepAliveThread.isAlive())) {
                    keepAliveThread = new KeepAliveThread();
                    keepAliveThread.setName("UDS Keep Alive");
                    keepAliveThread.setDaemon(true);
                    keepAliveThread.start();
                }

                setConnectionMode(newMode);
            } finally {
                changing = false;
            }
        }
    }

    /**
     * Internal method to set the current session.
     * @param session session to set.
     * @throws IOException if there is an issue closing an existing session.
     */
    protected void setSession(UDSSession session) throws IOException {
        UDSSession current = this.session;
        if (current != session) {
            if (current != null) {
                try {
                    current.close();
                } finally {
                    fireEvent(listener -> listener.onSessionClosed(this, current));
                }
            }

            this.session = session;
            if (session != null) {
                clearDataIdentifiers();

                fireEvent(listener -> listener.onSessionOpened(this, session));

                session.addListener(new UDSListener() {
                    @Override
                    public void onUDSFrameRead(UDSFrame frame) {
                        setLastFrameRead(System.currentTimeMillis());
                        fireEvent(listener -> listener.onUDSFrameRead(UDSConnection.this, frame));
                    }

                    @Override
                    public void onUDSFrameWrite(UDSFrame frame) {
                        setLastFrameSent(System.currentTimeMillis());
                        fireEvent(listener -> listener.onUDSFrameWrite(UDSConnection.this, frame));
                    }

                    @Override
                    public void onDisconnected(UDSSession session) {
                        try {
                            disconnect();
                        } catch (IOException e) {
                            Log.can().log(Level.WARNING, "Problem disconnecting UDS connection", e);
                        }

                        fireEvent(listener -> listener.onDisconnected(UDSConnection.this));
                    }
                });
            }
        }
    }

    protected abstract UDSSession newSession(SessionType type)
            throws IOException, TimeoutException, InterruptedException;

    @Override
    public final UDSSession connect(SessionType sessionType) throws IOException, TimeoutException, InterruptedException {
        UDSSession session = getSession();
        if (sessionType != this.sessionType) {
            disconnect();
            session = null;
        }

        if (session == null) {
            session = newSession(sessionType);
            setSession(session);

            if (session instanceof AsyncUDSSession asyncUDSSession) {
                asyncUDSSession.start();
            }

            setConnectionMode(ConnectionMode.IDLE);
            this.sessionType = sessionType;
        }

        return session;
    }

    @Override
    public void disconnect() throws IOException {
        if (session != null) {
            session.close();
            session = null;

            sessionType = null;
            setConnectionMode(ConnectionMode.DISCONNECTED);
        }
    }

    /**
     * Called by the UDSConnection class to indicate to a subclass that it should perform vendor-specific routines to
     * change the current connection mode. For example, this is where you should implement security access functionality
     * in order to place the ECU into an authorized session to read/write memory, etc. When this method returns, the
     * ECU should be in the requested session and should be ready to accept related commands (such as reading or
     * writing memory) with no risk of an authorization failure.
     *
     * @param newMode new connection mode that is being requested by the caller to UDSConnection.
     * @throws IOException if there is a protocol-level exception during the session change; session wasn't changed.
     * @throws TimeoutException if there was a timeout calling routines that would place the ECU into the requested
     *                          session; session wasn't changed
     * @throws InterruptedException if an interruption occurred during the session change; session may not have been
     *                              changed.
     */
    protected abstract void change(ConnectionMode newMode) throws IOException, TimeoutException, InterruptedException;

    @Override
    public void clearDTC() throws IOException, TimeoutException {
        try {
            try (var transaction = getSession().request(getECUComponent().getSendAddress(),
                    new UDSClearDTCInformationRequest(new byte[] {
                            (byte)0xFF, (byte)0xFF, (byte)0xFF
                    }))) {
                transaction.join();
            }
        } catch (IOException | TimeoutException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    @Override
    public List<Integer> readDTC() throws IOException, TimeoutException {
        try {
            try (var transaction = getSession().request(getECUComponent().getSendAddress(),
                    new UDSReadDTCRequest(DTC.REPORT_DTC_BY_MASK, DTC.MASK_CONFIRMED))) {
                UDSReadDTCResponse response = transaction.get();

                List<Integer> dtc = new ArrayList<>();;
                BitReader reader = new BitReader(response.getData());
                reader.readByte(); // Skip report type
                reader.readByte(); // Skip availability mask

                while (reader.remainingBytes() >= 4) {
                    dtc.add((int) (reader.read(24) & 0xFFFFFF));
                    reader.readByte(); // Skip the status bit
                }
                return dtc;

            }
        } catch (IOException | TimeoutException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    @Override
    public void resetECU(ECUResetMode mode) throws IOException, TimeoutException {
        try {
            try (var transaction = getSession().request(getECUComponent().getSendAddress(),
                    new UDSECUResetRequest(mode))) {
                transaction.join(5000);
            }
        } catch (IOException | TimeoutException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    @Override
    public byte[] readDID(short did) throws IOException, TimeoutException {
        try {
            try (var transaction = getSession().request(getECUComponent().getSendAddress(),
                    new UDSReadDataByIDRequest(did))) {
                var response = transaction.get();
                return response.getData();
            }
        } catch (IOException | TimeoutException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    /**
     * Gets the number of memory parameters for a new dynamically defined data identifier, given the provided list
     * of undefined parameters. The purpose of this function is to adequately size new dynamically defined data
     * identifiers within the ECU. Implementations should analyze the provided list and return the number of parameters,
     * counting from the beginning of the list, that can be accepted by the ECU to form a dynamically defined data
     * identifier. To create a data identifier with only 3 parameters (indices 0, 1, and 2 in the passed-in parameter
     * list), return 3 from this function. Returning 0 may result in an UnsupportedOperationException being thrown by
     * the caller. Some ECUs have a static limit, like 10, and in those cases no special logic is needed by the
     * implementation. For example, the Subaru DI ECU will return "REQUEST_OUT_OF_RANGE" when asked to create a DID
     * with 11 parameters. Returning a number greater than the parameter list size is acceptable, and should result in
     * a DID that is sized appropriately to the parameter list size; whichever number is least.
     *
     * @param parameters the list of parameters to possibly analyze return a DID size for.
     * @return maximum number of parameters for the next DID, or 0 if defining this DID is unsupported.
     */
    protected abstract int getNextDataIdentifierSize(List<MemoryParameter> parameters);

    /**
     * Gets the desired data identifier for a given index.
     * @param index index of the DID being created (0-indexed).
     * @return real DID number to use when defining this DID with the ECU.
     */
    protected int getDataIdentifier(int index) {
        return DataIdentifier.DYNAMICALLY_DEFINED.getBegin() + index;
    }

    /**
     * Defines a data identifier with the ECU, given a list of pre-sized parameters. This function should actually
     * declare the identifier in the ECU's state. A default implementation exists that declares DIDs at 0xF300 and
     * forward. It is expected that the defined dynamic data identifier will be ordered such that the order of the input
     * parameters list will match the order of any frames subsequently read from the DID.
     *
     * @param index the index, starting at zero, of the data identifier. For example, passing in 0 in this function
     *              might return 0xF300, 1 might return 0xF301, and so on.
     * @param parameters parameter list to define.
     * @return the DID number successfully declared in the ECU.
     */
    protected int defineDataIdentifier(int index, Variant variant, List<MemoryParameter> parameters)
            throws IOException, TimeoutException, InterruptedException {
        index = getDataIdentifier(index);
        index = index & 0xFFFF;

        ByteBuffer buffer = ByteBuffer.allocate(1 + (parameters.size() * 5));

        // Length and data length
        // 0x1 - data length, length (i.e. 0xFF = 255 bytes at address)
        // 0x4 - address length (i.e. 32 bit memory address / 0xFFFFFFFF)
        buffer.put((byte) 0x14);

        // Watch out - the order switches here from data length and memory to the inverse order:
        for (MemoryParameter parameter : parameters) {
            buffer.putInt((int) (parameter.getAddress().getOffset(variant) & 0xFFFFFFFFL));
            buffer.put((byte) (parameter.getScale().getFormat().getSize() & 0xFF));
        }

        // Set up new DID
        try {
            UDSDefineDataIdentifierResponse response = getSession().request(getECUComponent(),
                    new UDSDefineDataIdentifierRequest(DynamicallyDefineSubFunction.DEFINE_BY_ADDRESS,
                            index, buffer.array()));
        } catch (UDSNegativeResponseException nre) {
            throw new IOException(Frame.toHexString(buffer.array()), nre);
        } catch (IOException e) {
            throw new IOException(e);
        } catch (TimeoutException | InterruptedException e) {
            throw e;
        }

        return index;
    }

    protected void deleteDataIdentifiers() throws IOException, InterruptedException, TimeoutException {
        // Delete any prior DID(s)
        UDSSession session = getSession();

        if (session != null) {
            session.request(getECUComponent(),
                    new UDSDefineDataIdentifierRequest(DynamicallyDefineSubFunction.CLEAR,
                            DataIdentifier.DYNAMICALLY_DEFINED.getBegin()));
        }

        clearDataIdentifiers();
    }

    @Override
    public void setParameters(Variant variant, Set<MemoryParameter> parameters)
            throws IOException, TimeoutException, InterruptedException {
        SessionType sessionType = getSessionType();
        ConnectionMode connectionMode = getConnectionMode();

        if (sessionType != SessionType.NORMAL) {
            throw new IllegalStateException("Session type is not " + SessionType.NORMAL.name() +
                    "; it is currently " + sessionType);
        } else if (connectionMode != ConnectionMode.DATALOG) {
            throw new IllegalStateException("Connection mode is not " + ConnectionMode.DATALOG.name()
                    + "; it is currently " + connectionMode);
        } else if (isConnectionModeChanging()) {
            throw new IllegalStateException("Connection mode is changing");
        }

        // Find all the parameters that we can support.
        // If it's not supported, silently drop it from the list; let the UI take care of the rest.
        parameters = parameters.stream().filter(p -> p.getAddress().hasOffset(variant)).collect(Collectors.toSet());

        synchronized (parameterLock) {
            Set<MemoryParameter> currentParameters = getParameters();

            // If setting these parameters would cause effectively no change, don't bother re-commanding them with the
            // vehicle.
            if (parameters.containsAll(currentParameters) && currentParameters.containsAll(parameters)) {
                return;
            }

            // Clear any prior defined DIDs
            try {
                deleteDataIdentifiers();
            } catch (Exception ex) {
                Log.can().log(Level.WARNING, "Problem deleting old data identifiers", ex);
            }

            // Declare all the DIDs we need
            List<MemoryParameter> remaining = new ArrayList<>(parameters);
            for (int index = 0; !remaining.isEmpty(); index++) {
                int number = getNextDataIdentifierSize(remaining);
                if (number <= 0) {
                    throw new UnsupportedOperationException();
                }

                number = Math.min(remaining.size(), number);
                List<MemoryParameter> define = new ArrayList<>(number);
                for (int i = 0; i < number; i++) {
                    define.add(remaining.removeFirst());
                }

                int did = defineDataIdentifier(index, variant, define);
                addDataIdentifier(new DynamicallyDefinedDID(did, define));
            }
        }
    }

    protected void addDataIdentifier(DynamicallyDefinedDID did) {
        definedDIDS.add(did);
    }

    protected boolean removeDataIdentifier(DynamicallyDefinedDID did) {
        return definedDIDS.remove(did);
    }

    protected List<DynamicallyDefinedDID> getDefinedDataIdentifiers() {
        return definedDIDS;
    }

    protected void clearDataIdentifiers() {
        definedDIDS.clear();
    }

    protected Set<MemoryParameter> getParameters() {
        return getDefinedDataIdentifiers().stream()
                .flatMap(dd -> dd.getParameters().stream())
                .collect(Collectors.toSet());
    }

    @Override
    public MemoryFrame readFrame() throws IOException, TimeoutException, InterruptedException {
        if (getSessionType() != SessionType.NORMAL) {
            throw new IllegalStateException("Session type is not " + SessionType.NORMAL.name());
        } else if (getConnectionMode() != ConnectionMode.DATALOG) {
            throw new IllegalStateException("Connection mode is not " + ConnectionMode.DATALOG.name());
        } else if (isConnectionModeChanging()) {
            throw new IllegalStateException("Connection mode is changing");
        }

        MemoryFrame frame = new MemoryFrame();

        synchronized (parameterLock) {
            UDSReadDataByIDResponse response;

            List<DynamicallyDefinedDID> dids = getDefinedDataIdentifiers();
            for (DynamicallyDefinedDID did : dids) {
                try {
                    response = getSession().request(getECUComponent(), new UDSReadDataByIDRequest(did.getDid()));
                } catch (IOException e) {
                    throw new IOException(e);
                } catch (TimeoutException | InterruptedException e) {
                    throw e;
                }

                ByteArrayInputStream bais = new ByteArrayInputStream(response.getData());

                for (MemoryParameter parameter : did.getParameters()) {
                    byte[] data = parameter.newBuffer();
                    int read = bais.read(data);
                    if (read != data.length) {
                        throw new EOFException("Unexpected end of data: " + read + " != " + data.length);
                    }

                    reverse(data);
                    frame.setData(parameter, data);
                }
            }
        }

        fireEvent(listener -> listener.onMemoryFrameRead(this, frame));

        return frame;
    }

    /**
     * Internal class to structure each individual data identifier in the ECU, i.e. 0xF300, 0xF301... and so on.
     */
    protected static class DynamicallyDefinedDID {
        private final int did;
        private final List<MemoryParameter> parameters;

        public DynamicallyDefinedDID(int did, List<MemoryParameter> parameters) {
            this.did = did;
            this.parameters = parameters;
        }

        public int getDid() {
            return did;
        }

        public List<MemoryParameter> getParameters() {
            return parameters;
        }
    }

    /**
     * Internal class to help with issuing KeepAlives to the ECU to ensure any elevated session stays alive.
     */
    private class KeepAliveThread extends Thread {
        @Override
        public void run() {
            synchronized (stateObject) {
                while (getConnectionMode() != ConnectionMode.DISCONNECTED && session != null) {
                    long deadline = getLastFrameSent() + getKeepAliveInterval();
                    if (shouldSendKeepAlive(deadline)) {
                        try {
                            if (!keepAlive()) {
                                stateObject.wait(getKeepAliveInterval());
                            }
                            fireEvent(listener -> listener.onKeepAliveSent(UDSConnection.this));
                        } catch (IOException | TimeoutException e) {
                            Log.can().log(Level.WARNING, "Failed to send keep-alive message", e);
                            fireEvent(listener -> listener.onKeepAliveException(UDSConnection.this, e));

                            try {
                                stateObject.wait(getFailedKeepAlivePause());
                            } catch (InterruptedException ex) {
                                break;
                            }
                        } catch (InterruptedException e) {
                            throw new RuntimeException(e);
                        }
                    } else {
                        long toWait = deadline - System.currentTimeMillis();
                        if (toWait > 0L) {
                            try {
                                stateObject.wait(toWait);
                            } catch (InterruptedException e) {
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
}
