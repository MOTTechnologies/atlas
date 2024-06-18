package com.github.manevolent.atlas.connection;

import com.github.manevolent.atlas.connection.subaru.SubaruDIConnection;
import com.github.manevolent.atlas.protocol.j2534.J2534DeviceProvider;

import java.util.function.Supplier;

public enum ConnectionType {
    DEBUG("Debug", new DebugConnection.Factory()),
    SUBARU_DI("Subaru Direct Injection", new SubaruDIConnection.Factory());

    private final String name;
    private final ConnectionFactory factory;

    ConnectionType(String name, ConnectionFactory factory) {
        this.factory = factory;
        this.name = name;
    }

    public String getName() {
        return name;
    }

    @Override
    public String toString() {
        return getName();
    }

    public ConnectionFactory getFactory() {
        return factory;
    }

    public Connection createConnection(Supplier<J2534DeviceProvider<?>> deviceProvider) {
        return getFactory().createConnection(deviceProvider);
    }

    public Connection createConnection(J2534DeviceProvider<?> deviceProvider) {
        return getFactory().createConnection(deviceProvider);
    }
}
