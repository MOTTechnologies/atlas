package com.github.manevolent.atlas.ui.component.graph;

import com.github.manevolent.atlas.model.node.GraphNode;
import com.github.manevolent.atlas.model.node.NodeEndpoint;

import java.awt.*;

public interface EndpointComponent {

    GraphNode getGraphNode();

    NodeEndpoint<?> getEndpoint();

    Point getAnchorPoint();

}
