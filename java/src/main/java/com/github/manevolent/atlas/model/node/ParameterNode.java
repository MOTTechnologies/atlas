package com.github.manevolent.atlas.model.node;

import com.github.manevolent.atlas.model.*;
import org.kordamp.ikonli.Ikon;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import java.awt.Color;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ParameterNode extends AbstractGraphNode {
    private static final String outputName = "OUT";
    private static final String inputName = "IN";

    private MemoryParameter parameter;
    private NodeOutput<ParameterNode> output = new Output();
    private NodeInput<ParameterNode> input = new Input();

    public MemoryParameter getParameter() {
        return parameter;
    }

    public void setParameter(MemoryParameter parameter) {
        this.parameter = parameter;
    }

    @Override
    public List<? extends NodeInput<?>> getInputs() {
        return Collections.singletonList(input);
    }

    @Override
    public List<NodeOutput<?>> getOutputs() {
        return Collections.singletonList(output);
    }

    @Override
    public NodeOutput<?> getOutput(String name) {
        if (name.equals(outputName)) {
            return output;
        } else {
            throw new UnsupportedOperationException(name);
        }
    }

    @Override
    public NodeInput<?> getInput(String name) {
        if (name.equals(inputName)) {
            return input;
        } else {
            throw new UnsupportedOperationException(name);
        }
    }

    @Override
    public Ikon getIcon() {
        return CarbonIcons.SUMMARY_KPI;
    }

    @Override
    public String getLabel() {
        return parameter.getName();
    }

    @Override
    public Color getLabelColor() {
        return new java.awt.Color(83, 230, 66);
    }

    private static class Output implements NodeOutput<ParameterNode> {
        @Override
        public String getName() {
            return outputName;
        }

        @Override
        public String getLabel(ParameterNode instance) {
            String label = "Read";

            Scale scale = instance.getParameter().getScale();
            if (scale == null) {
                return label;
            }

            Unit unit = scale.getUnit();
            if (unit == null) {
                return label;
            }

            String parenthesis;
            if (unit == Unit.NONE) {
                parenthesis = scale.getFormat().toString();
            } else {
                parenthesis = unit.getText();
            }

            return label + " (" + parenthesis + ")";
        }

        @Override
        public Color getColor(ParameterNode node) {
            return new java.awt.Color(83, 230, 66);
        }
    }

    private static class Input implements NodeInput<ParameterNode> {
        @Override
        public String getName() {
            return inputName;
        }

        @Override
        public String getLabel(ParameterNode instance) {
            String label = "Write";

            Scale scale = instance.getParameter().getScale();
            if (scale == null) {
                return label;
            }

            Unit unit = scale.getUnit();
            if (unit == null) {
                return label;
            }

            String parenthesis;
            if (unit == Unit.NONE) {
                parenthesis = scale.getFormat().toString();
            } else {
                parenthesis = unit.getText();
            }

            return label + " (" + parenthesis + ")";
        }
    }
}
