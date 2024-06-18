package com.github.manevolent.atlas.connection;

import com.github.manevolent.atlas.protocol.uds.UDSFrame;

import com.github.manevolent.atlas.protocol.uds.UDSSession;

public interface UDSConnectionListener extends ConnectionListener {

    default void onSessionClosed(UDSConnection connection, UDSSession session) { }
    default void onSessionOpened(UDSConnection connection, UDSSession session) { }

    default void onUDSFrameRead(UDSConnection connection, UDSFrame read) { }
    default void onUDSFrameWrite(UDSConnection connection, UDSFrame write) { }

    default void onConnectionModeChanged(UDSConnection connection, ConnectionMode oldMode, ConnectionMode newMode) { }

}
