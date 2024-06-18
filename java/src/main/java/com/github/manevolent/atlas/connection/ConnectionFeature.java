package com.github.manevolent.atlas.connection;

public enum ConnectionFeature {

    SPY(SessionType.SPY, ConnectionMode.IDLE, "Spy/sniff CAN bus traffic"),
    FLASH_ROM(SessionType.NORMAL, ConnectionMode.FLASH_ROM, "Write new calibrations"),
    READ_MEMORY(SessionType.NORMAL, ConnectionMode.READ_MEMORY, "Read memory"),
    DATALOG(SessionType.NORMAL, ConnectionMode.DATALOG, "Data logging");

    private final SessionType sessionType;
    private final ConnectionMode connectionMode;
    private final String name;

    ConnectionFeature(SessionType sessionType, ConnectionMode connectionMode, String name) {
        this.sessionType = sessionType;
        this.connectionMode = connectionMode;
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public SessionType getSessionType() {
        return sessionType;
    }

    public ConnectionMode getConnectionMode() {
        return connectionMode;
    }
}
