package com.github.manevolent.atlas.connection;

import com.github.manevolent.atlas.model.Project;
import com.github.manevolent.atlas.protocol.j2534.J2534DeviceProvider;
import com.github.manevolent.atlas.protocol.j2534.J2534DeviceType;
import com.github.manevolent.atlas.ui.util.Devices;
import org.checkerframework.checker.nullness.qual.NonNull;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Optional;

import java.util.concurrent.TimeoutException;

public abstract class AbstractConnectionManager implements ConnectionManager {
    private Connection connection;

    protected abstract Project getProject();

    protected abstract ConnectionType getConnectionType();

    protected abstract void handleException(Throwable e);

    protected J2534DeviceType getDeviceType() {
        return Devices.getType();
    }

    protected J2534DeviceProvider<?> getProvider(J2534DeviceType type) {
        return type.getProvider();
    }

    @Override
    public Optional<Connection> getConnection() {
        return Optional.ofNullable(connection);
    }

    @Override
    public Connection tryConnection(@NonNull SessionType sessionType)
            throws IOException, InterruptedException, TimeoutException {
        Optional<Connection> existing = getConnection(sessionType);
        if (existing.isEmpty()) {
            return openConnection(sessionType, ConnectionMode.IDLE);
        } else {
            return existing.get();
        }
    }

    @Override
    public Optional<Connection> requireConnection(@NonNull SessionType sessionType) {
        Optional<Connection> existing = getConnection(sessionType);

        if (existing.isEmpty()) {
            Connection established;

            try {
                established = openConnection(sessionType, ConnectionMode.IDLE);
            } catch (Throwable e) {
                handleException(e);
                established = null;
            }

            return Optional.ofNullable(established);
        } else {
            return existing;
        }
    }

    @Override
    public Optional<Connection> requireConnection(@NonNull ConnectionFeature feature) {
        return requireConnection(feature.getSessionType(), feature.getConnectionMode());
    }

    @Override
    public Optional<Connection> requireConnection(@NonNull ConnectionMode connectionMode) {
        Connection connection = getConnection().get();
        return requireConnection(connection.getSessionType(), connectionMode);
    }

    @Override
    public Optional<Connection> requireConnection(@NonNull SessionType sessionType,
                                                  @NonNull ConnectionMode connectionMode) {
        Optional<Connection> existing = getConnection(sessionType);

        existing.ifPresent(c -> {
            try {
                c.changeConnectionMode(connectionMode);
            } catch (Exception e) {
                handleException(e);
            }
        });

        if (existing.isEmpty()) {
            Connection established;

            try {
                established = openConnection(sessionType, connectionMode);
            } catch (Throwable e) {
                handleException(e);
                established = null;
            }

            return Optional.ofNullable(established);
        } else {
            return existing;
        }
    }

    protected Connection createConnection(ConnectionType type, J2534DeviceProvider<?> provider) {
        return getConnectionType().createConnection(provider);
    }

    protected Connection createConnection(SessionType sessionType)
            throws IOException, InterruptedException, TimeoutException {
        ConnectionType connectionType = getConnectionType();
        if (connectionType == null) {
            throw new IllegalArgumentException("Please set a connection type for this" +
                    " project so communication can be established.");
        }

        J2534DeviceType deviceType = getDeviceType();
        J2534DeviceProvider<?> provider = getProvider(deviceType);
        Connection connection = createConnection(connectionType, provider);
        if (connection != null) {
            Project project = getProject();

            if (project == null) {
                throw new IllegalStateException("No project is currently active.");
            }

            connection.setProject(project);

            //noinspection resource
            connection.connect(sessionType);
        }

        return connection;
    }

    protected Connection openConnection(ConnectionFeature feature)
            throws IOException, InterruptedException, TimeoutException {
        if (feature == null) {
            throw new NullPointerException("feature");
        }

        return openConnection(feature.getSessionType(), feature.getConnectionMode());
    }

    protected synchronized Connection openConnection(SessionType sessionType, ConnectionMode connectionMode)
            throws IOException, InterruptedException, TimeoutException {
        if (getProject() == null) {
            throw new IllegalStateException("No project is currently loaded.");
        }

        if (!sessionType.supportsMode(connectionMode)) {
            throw new UnsupportedEncodingException(sessionType.name() + " does not support " + connectionMode);
        }

        // Try to use an existing connection object
        Connection connection = this.connection;
        if (connection != null && !canReuseConnection(connection, sessionType)) {
            connection.disconnect();
            connection = null;
        }

        // Establish a new connection if necessary
        if (connection == null) {
            connection = createConnection(sessionType);

            // Strange scenario, but add a check to avoid an NPE later
            if (connection == null) {
                throw new NullPointerException("connection");
            }
        }

        AutoCloseable closeable = connection.connect(sessionType);

        try {
            connection.changeConnectionMode(sessionType, connectionMode);
        } catch (IOException | TimeoutException | InterruptedException ex) {
            try {
                closeable.close();
            } catch (Exception e) {
                ex.addSuppressed(e);
            }

            throw ex;
        }

        return this.connection = connection;
    }

}
