package com.github.manevolent.atlas.model.node;

import com.github.manevolent.atlas.model.AbstractAnchored;
import com.github.manevolent.atlas.ui.component.graph.NodeComponent;

import java.util.ArrayList;
import java.util.List;

public abstract class AbstractGraphNode extends AbstractAnchored implements GraphNode {
    // The upper-left corner of the node itself
    private float x = 0, y = 0;
    private GraphModule module;

    @Override
    public float getY() {
        return y;
    }

    @Override
    public void setY(float y) {
        this.y = y;
    }

    @Override
    public float getX() {
        return x;
    }

    @Override
    public void setX(float x) {
        this.x = x;
    }

    @Override
    public GraphModule getModule() {
        return module;
    }

    @Override
    public void setModule(GraphModule module) {
        this.module = module;
    }

    @Override
    public NodeConnection createConnection(NodeEndpoint<?> mine, GraphNode them, NodeEndpoint<?> theirs) {
        if (mine instanceof NodeInput<?> input && !getInputs().contains(mine)) {
            throw new IllegalArgumentException("Input doesn't exist on " + toString() + ": " + mine.toString());
        } else if (mine instanceof NodeOutput<?> output && !getOutputs().contains(mine)) {
            throw new IllegalArgumentException("Output doesn't exist on " + toString() + ": " + mine.toString());
        } else if (theirs instanceof NodeInput<?> input && !them.getInputs().contains(theirs)) {
            throw new IllegalArgumentException("Input doesn't exist on " + toString() + ": " + mine.toString());
        } else if (theirs instanceof NodeOutput<?> output && !them.getOutputs().contains(output)) {
            throw new IllegalArgumentException("Input doesn't exist on " + toString() + ": " + mine.toString());
        }

        if (mine instanceof NodeInput<?> && theirs instanceof NodeInput<?>) {
            throw new IllegalArgumentException("Cannot connect two inputs");
        } else if (mine instanceof NodeOutput<?> && theirs instanceof NodeOutput<?>) {
            throw new IllegalArgumentException("Cannot connect two outputs");
        }

        NodeConnection connection = new NodeConnection();
        if (mine instanceof NodeInput<?> input && theirs instanceof NodeOutput<?> output) {
            connection.setTarget(this);
            connection.setInputName(input.getName());

            connection.setSource(them);
            connection.setOutputName(output.getName());
        } else if (mine instanceof NodeOutput<?> output && theirs instanceof NodeInput<?> input) {
            connection.setSource(this);
            connection.setOutputName(output.getName());

            connection.setTarget(them);
            connection.setInputName(input.getName());
        } else {
            // This shouldn't happen unless we have anything other that inputs & outputs
            throw new UnsupportedOperationException("Unsupported endpoint configuration: " + mine + " -> " + theirs);
        }

        onConnected(connection);
        them.onConnected(connection);

        return connection;
    }


}
