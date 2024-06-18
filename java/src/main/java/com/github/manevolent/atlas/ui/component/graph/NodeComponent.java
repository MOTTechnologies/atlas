package com.github.manevolent.atlas.ui.component.graph;

import com.github.manevolent.atlas.model.node.GraphNode;
import com.github.manevolent.atlas.model.node.NodeEndpoint;
import com.github.manevolent.atlas.model.node.NodeInput;
import com.github.manevolent.atlas.model.node.NodeOutput;

import java.awt.*;
import java.util.List;

public interface NodeComponent {

    GraphNode getGraphNode();

    List<EndpointComponent> setupEndpoints();

    List<ConnectionComponent> setupConnections();

    Point getAnchorPoint(NodeEndpoint<?> endpoint);

    Point getOutputAnchorPoint(NodeOutput<?> endpoint);

    Point getInputAnchorPoint(NodeInput<?> endpoint);

    void highlight();

    boolean setValue(Float value);

    Float getValue();

    boolean isShowingOnScreen();

}
