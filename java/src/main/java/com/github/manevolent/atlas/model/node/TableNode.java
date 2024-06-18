package com.github.manevolent.atlas.model.node;

import com.github.manevolent.atlas.model.*;
import org.kordamp.ikonli.Ikon;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import java.awt.Color;
import java.util.*;
import java.util.List;

public class TableNode extends AbstractGraphNode {
    private static final String outputName = "OUT";

    private static final Map<Axis, Input> inputLookupMap = new HashMap<>();

    static {
        inputLookupMap.put(Axis.X, Input.X);
        inputLookupMap.put(Axis.Y, Input.Y);
        inputLookupMap.put(Axis.Z, Input.Z);
        inputLookupMap.put(Axis.W, Input.W);
    }

    private Table table;
    private NodeOutput<TableNode> output = new Output();

    public Table getTable() {
        return table;
    }

    public void setTable(Table table) {
        this.table = table;
    }

    @Override
    public List<? extends NodeInput<?>> getInputs() {
        return table.getAxes().keySet().stream()
                .map(inputLookupMap::get)
                .map(i -> (NodeInput<?>) i)
                .toList();
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
        return Input.valueOf(name);
    }

    @Override
    public Ikon getIcon() {
        return CarbonIcons.DATA_TABLE;
    }

    @Override
    public String getLabel() {
        return table.getName();
    }

    @Override
    public Color getLabelColor() {
        return table.getTreeIconColor();
    }

    private static class Output implements NodeOutput<TableNode> {
        @Override
        public String getName() {
            return outputName;
        }

        @Override
        public String getLabel(TableNode instance) {
            String label = "Output";

            Series series = instance.getTable().getData();
            if (series == null) {
                return label;
            }

            Scale scale = series.getScale();
            if (scale == null) {
                return label;
            }

            Unit unit = scale.getUnit();
            if (unit == null) {
                return label;
            }

            String parenthesis;
            if (unit == Unit.NONE) {
                parenthesis = series.getFormat().toString();
            } else {
                parenthesis = unit.getText();
            }

            return label + " (" + parenthesis + ")";
        }

        @Override
        public Color getColor(TableNode instance) {
            return instance.getTable().getTreeIconColor();
        }
    }

    public enum Input implements NodeInput<TableNode> {
        X(Axis.X, "X"),
        Y(Axis.Y, "Y"),
        Z(Axis.Z, "Z"),
        W(Axis.W, "W");

        private final Axis axis;
        private final String label;

        Input(Axis axis, String label) {
            this.axis = axis;
            this.label = label;
        }

        @Override
        public String getName() {
            return name();
        }

        @Override
        public String getLabel(TableNode instance) {
            Series series = instance.getTable().getSeries(axis);
            if (series == null) {
                return label;
            }

            Scale scale = series.getScale();
            if (scale == null) {
                return label;
            }

            Unit unit = series.getUnit();
            if (unit == null) {
                return label;
            }

            String parenthesis;
            if (unit == Unit.NONE) {
                parenthesis = series.getFormat().toString();
            } else {
                parenthesis = unit.getText();
            }

            return label + " (" + parenthesis + ")";
        }

        public Axis getAxis() {
            return axis;
        }
    }
}
