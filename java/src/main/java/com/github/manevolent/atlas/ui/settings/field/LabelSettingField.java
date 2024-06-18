package com.github.manevolent.atlas.ui.settings.field;

import javax.swing.*;
import java.awt.*;
import java.util.Arrays;

public class LabelSettingField extends AbstractSettingField {
    private final java.util.List<JLabel> labels;

    public LabelSettingField(String name, java.util.List<JLabel> labels) {
        super(name, null);

        this.labels = labels;
    }

    public LabelSettingField(String name, JLabel... labels) {
        super(name, null);

        this.labels = Arrays.asList(labels);
    }

    @Override
    public JComponent getInputComponent() {
        JPanel panel = new JPanel(new GridLayout(0, 1));
        labels.forEach(panel::add);
        return panel;
    }

    @Override
    public boolean apply() {
        return true;
    }

    @Override
    public boolean isDirty() {
        return false;
    }

    @Override
    public int getLabelAlignment() {
        return SwingConstants.TOP;
    }
}
