package com.github.manevolent.atlas.connection;

import org.checkerframework.checker.nullness.qual.NonNull;

import java.io.IOException;
import java.util.Optional;
import java.util.concurrent.TimeoutException;

public interface ConnectionManager {

    /**
     * Utility method to determine if a connection can be reused.
     *
     * @param existing existing connection to check for possible reuse.
     * @param sessionType intended session type to use the connection for following a true result from this method.
     * @return true if the connection can be reused, false otherwise.
     */
    default boolean canReuseConnection(Connection existing, SessionType sessionType) {
        if (existing == null) {
            return false;
        } else if (!existing.isConnected()) {
            return false;
        } else {
            return existing.getSessionType() == sessionType;
        }
    }

    /**
     * Gets the current connection as an Optional.
     * @return optional of connection.
     */
    Optional<Connection> getConnection();

    /**
     * Gets the current connection mode, or null if no mode is set.
     * @return connection mode, or null.
     */
    default ConnectionMode getConnectionMode() {
        return getConnection().map(Connection::getConnectionMode).orElse(null);
    }

    /**
     * Gets the current connection as an Optional, provided it has the correct session type.
     * @return optional of connection.
     */
    default Optional<Connection> getConnection(SessionType sessionType) {
        return getConnection().filter(c -> canReuseConnection(c, sessionType));
    }

    /**
     * Gets the current connection as an Optional, provided it in configured to use the correct connection feature.
     * @param connectionFeature feature
     * @return optional of connection.
     */
    default Optional<Connection> getConnection(ConnectionFeature connectionFeature) {
        return getConnection(connectionFeature.getSessionType())
                .filter(connection -> connection.getConnectionMode() == connectionFeature.getConnectionMode());
    }

    /**
     * Gets a connection, reconnecting or changing its session type if necessary in order to
     * produce a Connection instance that is connected with the appropriate session type.
     *
     * @param sessionType the session type to use for this connection.
     * @return connection instance.
     */
    Optional<Connection> requireConnection(@NonNull SessionType sessionType);

    /**
     * Gets a connection, reconnecting or changing its connection mode if necessary in order to
     * produce a Connection instance that is connected with the appropriate session type and connection mode.
     *
     * @param feature the feature to use for this connection.
     * @return connection instance.
     */
    default Optional<Connection> requireConnection(@NonNull ConnectionFeature feature) {
        return requireConnection(feature.getSessionType(), feature.getConnectionMode());
    }

    /**
     * Gets a connection, reconnecting or changing its session type if necessary in order to
     * produce a Connection instance that is connected with the appropriate session type.
     *
     * @param sessionType the session type to use for this connection.
     * @param connectionMode the connection mode to use for this connection.
     * @return connection instance.
     */
    Optional<Connection> requireConnection(@NonNull SessionType sessionType, @NonNull ConnectionMode connectionMode);

    /**
     * Gets a connection, reconnecting or changing its session type if necessary in order to
     * produce a Connection instance that is connected with the appropriate session type. Uses the current session type.
     *
     * @param connectionMode the connection mode to use for this connection.
     * @return connection instance.
     */
    Optional<Connection> requireConnection(@NonNull ConnectionMode connectionMode);

    /**
     * Tries to establish a connection, and possibly fails, throwing the exception to the caller.
     * @param sessionType the session type to use for this connection.
     * @return connection instance.
     * @throws IOException
     * @throws InterruptedException
     * @throws TimeoutException
     */
    Connection tryConnection(@NonNull SessionType sessionType) throws IOException, InterruptedException, TimeoutException;

    /**
     * Finds if the connection is established.
     * @return true if the connected is established, false otherwise.
     */
    default boolean isConnected() {
        return getConnection().map(Connection::isConnected).orElse(false);
    }

}
