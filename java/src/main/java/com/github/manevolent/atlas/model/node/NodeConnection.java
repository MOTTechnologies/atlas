package com.github.manevolent.atlas.model.node;

import com.github.manevolent.atlas.model.AbstractAnchored;

public class NodeConnection extends AbstractAnchored {
    private GraphNode source;
    private String outputName;

    private GraphNode target;
    private String inputName;

    public NodeConnection() {

    }

    public NodeConnection(GraphNode source, NodeOutput<?> output, GraphNode target, NodeInput<?> input) {
        this.source = source;
        this.outputName = output.getName();
        this.target = target;
        this.inputName = input.getName();
    }

    public GraphNode getSource() {
        return source;
    }

    public void setSource(GraphNode source) {
        this.source = source;
    }

    public NodeOutput<?> getOutput() {
        if (outputName == null) {
            return null;
        }

        return source.getOutput(outputName);
    }

    public String getOutputName() {
        return outputName;
    }

    public void setOutputName(String outputName) {
        this.outputName = outputName;
    }

    public GraphNode getTarget() {
        return target;
    }

    public void setTarget(GraphNode target) {
        this.target = target;
    }

    public NodeInput<?> getInput() {
        if (inputName == null) {
            return null;
        }

        return target.getInput(inputName);
    }

    public String getInputName() {
        return inputName;
    }

    public void setInputName(String inputName) {
        this.inputName = inputName;
    }

    @Override
    public boolean equals(Object obj) {
        return obj instanceof NodeConnection conn && equals(conn);
    }

    public boolean equals(NodeConnection other) {
        return other.getOutput() == getOutput() && other.getInput() == getInput()
                && other.getSource() == getSource() && other.getTarget() == getTarget();
    }
}
