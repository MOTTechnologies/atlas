package com.github.manevolent.atlas.model.node;

import com.github.manevolent.atlas.ui.util.Fonts;
import com.github.manevolent.atlas.ui.util.Inputs;
import org.kordamp.ikonli.Ikon;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class DocumentationNode extends AbstractGraphNode {
    private static final Color color = new Color(0x305Ca0);
    private final List<NodeInput<?>> inputs = new ArrayList<>();
    private final List<NodeOutput<?>> outputs = new ArrayList<>();

    private int numberInputs = 1;
    private int numberOutputs = 1;

    private String text;

    public int getNumberInputs() {
        return numberInputs;
    }

    public void setNumberInputs(int numberInputs) {
        this.numberInputs = numberInputs;

        while (inputs.size() < numberInputs) {
            inputs.add(new Input(inputs.size()));
        }

        while (!inputs.isEmpty() && inputs.size() > numberInputs) {
            inputs.removeLast();
        }
    }

    public int getNumberOutputs() {
        return numberOutputs;
    }

    public void setNumberOutputs(int numberOutputs) {
        this.numberOutputs = numberOutputs;


        while (outputs.size() < numberOutputs) {
            outputs.add(new Output(outputs.size()));
        }

        while (!outputs.isEmpty() && outputs.size() > numberOutputs) {
            outputs.removeLast();
        }
    }

    public String getText() {
        return text;
    }

    public void setText(String text) {
        this.text = text;
    }

    @Override
    public Ikon getIcon() {
        return CarbonIcons.INFORMATION_FILLED;
    }

    @Override
    public String getLabel() {
        return "Documentation";
    }

    @Override
    public Color getLabelColor() {
        return color;
    }

    @Override
    public JComponent getSettingComponent() {
        JTextArea textArea = Inputs.textArea(getText(), this::setText);
        textArea.setFont(Fonts.VALUE_FONT);
        textArea.setWrapStyleWord(true);
        textArea.setLineWrap(true);
        return textArea;
    }

    @Override
    public List<? extends NodeInput<?>> getInputs() {
        return inputs;
    }

    @Override
    public List<? extends NodeOutput<?>> getOutputs() {
        while (outputs.size() < numberOutputs) {
            outputs.add(new Output(outputs.size()));
        }

        return outputs;
    }

    @Override
    public NodeInput<?> getInput(String name) {
        int number = Integer.parseInt(name);
        if (number < 0) {
            throw new IllegalArgumentException(name);
        }

        while (inputs.size() < number + 1) {
            inputs.add(new Input(inputs.size()));
        }

        return inputs.get(number);
    }

    @Override
    public NodeOutput<?> getOutput(String name) {
        int number = Integer.parseInt(name);
        if (number < 0) {
            throw new IllegalArgumentException(name);
        }

        while (outputs.size() < number + 1) {
            outputs.add(new Output(outputs.size()));
        }

        return outputs.get(number);
    }

    private class Input implements NodeInput<DocumentationNode> {
        private final int number;

        private Input(int number) {
            this.number = number;
        }

        @Override
        public String getName() {
            return Integer.toString(number);
        }

        @Override
        public String getLabel(DocumentationNode instance) {
            switch (number) {
                case 0:
                    return "X";
                case 1:
                    return "Y";
                case 2:
                    return "Z";
                default:
                    return Integer.toHexString(number + 1);
            }
        }
    }

    private class Output implements NodeOutput<DocumentationNode> {
        private final int number;

        private Output(int number) {
            this.number = number;
        }

        @Override
        public Color getColor(DocumentationNode node) {
            return color;
        }

        @Override
        public String getName() {
            return Integer.toString(number);
        }

        @Override
        public String getLabel(DocumentationNode instance) {
            if (numberOutputs <= 1) {
                return "Output";
            }

            switch (number) {
                case 0:
                    return "A";
                case 1:
                    return "B";
                case 2:
                    return "C";
                default:
                    return Integer.toHexString(number + 1);
            }
        }
    }
}
