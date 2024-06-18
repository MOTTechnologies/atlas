package com.github.manevolent.atlas.connection;

import com.github.manevolent.atlas.model.Project;
import com.github.manevolent.atlas.protocol.j2534.J2534Device;

public interface ConnectionListener {

    default void onDisconnected(Connection connection) { }

    default void onDeviceFound(Connection connection, J2534Device device) { }

    default void onProjectChanging(Connection connection, Project oldProject, Project newProject) { }

    default void onProjectChanged(Connection connection, Project newProject) { }

    default void onKeepAliveSent(Connection connection) { }

    default void onKeepAliveException(Connection connection, Throwable e) { }

    default void onMemoryFrameRead(Connection connection, MemoryFrame frame) { }

}
