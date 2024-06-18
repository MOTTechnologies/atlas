package com.github.manevolent.atlas.ui.settings.field;

import com.github.manevolent.atlas.settings.IntegerSetting;
import com.github.manevolent.atlas.settings.Settings;

import javax.swing.*;
import java.util.function.Consumer;
import java.util.function.Function;

public class IntegerSettingField extends AbstractSettingField {
    private final Function<Integer, Boolean> apply;
    private final JSpinner spinner;

    private int value;
    private boolean dirty;

    public IntegerSettingField(String name,
                               String tooltip,
                               int defaultValue,
                               int min, int max,
                               Function<Integer, Boolean> apply,
                               Consumer<Integer> changed) {
        super(name, tooltip);

        this.value = defaultValue;
        this.apply = apply;

        SpinnerNumberModel model = new SpinnerNumberModel(defaultValue, min, max, 1);
        spinner = new JSpinner(model);

        ((JSpinner.DefaultEditor)spinner.getEditor()).getTextField().setHorizontalAlignment(JTextField.LEFT);
        spinner.addChangeListener(e -> {
            value = (int) spinner.getValue();
            changed.accept(value);
            dirty = true;
            fireFieldChanged();
        });
    }

    public IntegerSettingField(String name,
                               String tooltip,
                               int min, int max,
                               IntegerSetting setting) {
        this(name, tooltip,
                setting.get(),
                min, max,
                appliedValue -> {
                    setting.set(appliedValue);
                    return true;
                },
                changed -> { });
    }

    @Override
    public JComponent getInputComponent() {
        return spinner;
    }

    @Override
    public boolean apply() {
        boolean applied = apply.apply(value);
        if (applied) {
            dirty = false;
        }
        return applied;
    }

    @Override
    public boolean isDirty() {
        return dirty;
    }
}