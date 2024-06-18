package com.github.manevolent.atlas.connection;

import com.github.manevolent.atlas.model.*;
import com.github.manevolent.atlas.protocol.uds.flag.ECUResetMode;
import com.github.manevolent.atlas.protocol.uds.UDSSession;
import com.github.manevolent.atlas.ui.behavior.ProgressListener;

import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeoutException;

public interface Connection {

    /**
     * Gets all supported platforms for this connection.
     * @return list of supported platforms.
     */
    List<Platform> getPlatforms();

    /**
     * Gets this connection's type
     * @return connection type
     */
    ConnectionType getType();

    /**
     * Gets this connection's session type
     * @return connection type
     */
    SessionType getSessionType();

    /**
     * Finds if the connection has an active hardware connection to the vehicle.
     * @return true if a connection has been established, false otherwise
     */
    boolean isConnected();

    /**
     * Sets the project associated with this connection.
     * @param project project instance.
     */
    void setProject(Project project);

    /**
     * Gets the set of features supported by this connection.
     * @return supported feature set.
     */
    Set<ConnectionFeature> getFeatures();

    /**
     * Gets the project associated with this connection.
     * @return project.
     */
    Project getProject();

    /**
     * Gets the current connection mode with the ECU.
     * @return connection mode.
     */
    ConnectionMode getConnectionMode();

    /**
     * Finds if the connection mode is changing
     * @return true if the connection mode is actively changing.
     */
    boolean isConnectionModeChanging();

    /**
     * Switches connection modes, performing any session deconstruction/construction operations necessary. For UDS-based
     * vehicles, this essentially amounts to changing a security access level and entering or exiting certain diagnostic
     * session states (i.e. a programming session).
     *
     * However, the ConnectionMode enumerator exposes these functions through your intent. Pass a value such as
     * FLASH_ROM to instruct the connection implementation to determine how best to enter a programming session with
     * the ECU, or READ_MEMORY to instruct the ECU, through the connection API, to unlock itself and provide the
     * highest level of memory reading privilege possible.
     *
     * @param sessionType new session type.
     * @param newMode new connection mode.
     * @throws IOException
     * @throws TimeoutException
     */
    void changeConnectionMode(SessionType sessionType, ConnectionMode newMode)
            throws IOException, TimeoutException, InterruptedException;

    /**
     * Switches connection modes, performing any session deconstruction/construction operations necessary. For UDS-based
     * vehicles, this essentially amounts to changing a security access level and entering or exiting certain diagnostic
     * session states (i.e. a programming session).
     *
     * However, the ConnectionMode enumerator exposes these functions through your intent. Pass a value such as
     * FLASH_ROM to instruct the connection implementation to determine how best to enter a programming session with
     * the ECU, or READ_MEMORY to instruct the ECU, through the connection API, to unlock itself and provide the
     * highest level of memory reading privilege possible.
     *
     * @param newMode new connection mode.
     * @throws IOException
     * @throws TimeoutException
     */
    default void changeConnectionMode(ConnectionMode newMode)
            throws IOException, TimeoutException, InterruptedException {
        SessionType sessionType = getSessionType();
        if (sessionType == null) {
            sessionType = SessionType.NORMAL;
        }

        changeConnectionMode(sessionType, newMode);
    }


    /**
     * Switches connection modes, performing any session deconstruction/construction operations necessary. For UDS-based
     * vehicles, this essentially amounts to changing a security access level and entering or exiting certain diagnostic
     * session states (i.e. a programming session).
     *
     * However, the ConnectionMode enumerator exposes these functions through your intent. Pass a value such as
     * FLASH_ROM to instruct the connection implementation to determine how best to enter a programming session with
     * the ECU, or READ_MEMORY to instruct the ECU, through the connection API, to unlock itself and provide the
     * highest level of memory reading privilege possible.
     *
     * @param feature feature to enable.
     * @throws IOException
     * @throws TimeoutException
     */
    default void changeConnectionMode(ConnectionFeature feature)
            throws IOException, TimeoutException, InterruptedException {
        changeConnectionMode(feature.getSessionType(), feature.getConnectionMode());
    }

    /**
     * Instructs the ECU to change the active set of memory parameters. This is primarily used in a datalog session and
     * should only be set or changed when that connection mode is successfully entered/activated.
     *
     * @param parameters set of memory parameters to apply to the ECU's active data-logging session.
     */
    void setParameters(Variant variant, Set<MemoryParameter> parameters) throws IOException, TimeoutException, InterruptedException;

    /**
     * Reads a frame of memory from the ECU's RAM using the previously provided memory parameters. To change the memory
     * frame, see setParameters.
     *
     * @return memory frame if one was available, null otherwise.
     */
    MemoryFrame readFrame() throws IOException, TimeoutException, InterruptedException;

    /**
     * Gets an active session, if one exists.
     * @return active session, null otherwise.
     * @throws IOException
     * @throws TimeoutException
     */
    UDSSession getSession();

    /**
     * Establishes a connection with the ECU, often sending pings and other types of validation.
     * @return the session, once fully established.
     * @throws IOException
     * @throws TimeoutException
     */
    UDSSession connect(SessionType sessionType) throws IOException, TimeoutException, InterruptedException;

    /**
     * Clears DTC from the vehicle.
     * @throws IOException
     * @throws TimeoutException
     */
    void clearDTC() throws IOException, TimeoutException;

    /**
     * Reads stored DTC
     * @return stored DTC
     */
    List<Integer> readDTC() throws IOException, TimeoutException;

    /**
     * Gets the maximum memory read size for this connection.
     * @return maximum memory read size, in bytes.
     */
    default int getMaximumReadSize() {
        return 0xFF;
    }

    /**
     * Reads a block of memory
     * @param address address to start the memory read from
     * @param length number of bytes to read
     * @return bytes read
     */
    byte[] readMemory(MemoryAddress address, Variant variant, int length) throws IOException, TimeoutException, InterruptedException;

    /**
     * Reads a block of memory using the maximum memory read size
     * @param address address to start the memory read from
     * @return bytes read
     */
    default byte[] readMemory(MemoryAddress address, Variant variant) throws IOException, TimeoutException, InterruptedException {
        return readMemory(address, variant, getMaximumReadSize());
    }

    /**
     * Resets the ECU
     * @param mode reset mode to perform.
     */
    void resetECU(ECUResetMode mode) throws IOException, TimeoutException;

    /**
     * Reads a single DID from the ECU
     * @param did DID to read
     * @return data from the did
     */
    byte[] readDID(short did) throws IOException, TimeoutException;

    /**
     * Identifies the platform for this ECU. This is important for checksum calculation and calibration writing.
     * @return platform object.
     */
    Platform identify() throws IOException, TimeoutException, InterruptedException, UnknownPlatformException;


    /**
     * Writes a new calibration to the ECU, permanently. Make sure the ECU has entered the FLASH_ROM connection mode
     * before calling this method; you can use setConnectionMode(ConnectionMode) to accomplish this. All appropriate
     * checksums and flash encryption are expected to be performed before this method, with the intention of there being
     * little chance of missing any critical operations to ensure ECU acceptance of the new calibration.
     *
     * @param platform platform being calibrated.
     * @param calibration calibration to flash to the ECU's permanent storage.
     * @param progressListener a listener to report back to with progress updates.
     * @return a FlashResult object describing the outcome of the calibration writing procedure.
     */
    FlashResult writeCalibration(Platform platform, Calibration calibration, ProgressListener progressListener)
            throws FlashException;

    /**
     * Reads the current calibration from the ECU.
     * @param platform platform to read the calibration for.
     * @param progressListener a listener to report back to with progress updates.
     * @return the full calibration for the vehicle
     */
    Calibration readCalibration(Platform platform, ProgressListener progressListener)
            throws IOException, TimeoutException, InterruptedException;

    /**
     * Finds if the connection is currently in a spying state
     * @return true if spying, false if otherwise
     */
    default boolean isSpying() {
        return getSessionType() == SessionType.SPY;
    }

    /**
     * Immediately disconnects any active session.
     * @throws IOException
     */
    void disconnect() throws IOException;

}
