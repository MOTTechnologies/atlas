package com.github.manevolent.atlas.ui.behavior;

import com.github.manevolent.atlas.connection.Connection;

public interface ConnectionListener {

    void onDisconnected(Connection connection);

}
