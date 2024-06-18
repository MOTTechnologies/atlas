package com.github.manevolent.atlas.ui.component.graph;

import com.github.manevolent.atlas.model.node.NodeConnection;

public class DefaultConnectionComponent implements ConnectionComponent {
    private final NodeConnection connection;

    public DefaultConnectionComponent(NodeConnection connection) {
        this.connection = connection;
    }

    @Override
    public NodeConnection getConnection() {
        return connection;
    }
}
