package com.github.manevolent.atlas.connection;

import com.google.common.collect.Sets;

import java.util.Set;

public enum SessionType {
    NORMAL(Sets.newHashSet(ConnectionMode.values())),
    SPY(Sets.newHashSet(ConnectionMode.DISCONNECTED, ConnectionMode.IDLE));

    private final Set<ConnectionMode> supportedModes;
    SessionType(Set<ConnectionMode> supportedModes) {
        this.supportedModes = supportedModes;
    }

    public boolean supportsMode(ConnectionMode mode) {
        return supportedModes.contains(mode);
    }
}
