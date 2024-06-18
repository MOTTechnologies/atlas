package com.github.manevolent.atlas.ui.settings.field;

import com.github.manevolent.atlas.ui.util.Inputs;

import javax.swing.*;
import java.util.Collection;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Function;

public class ListSettingField<T> extends AbstractSettingField {
    private final Function<T, Boolean> apply;
    private final JComboBox<T> comboBox;

    private boolean dirty;

    public ListSettingField(String name,
                            String tooltip,
                            Collection<T> options,
                            T defaultValue,
                            Function<T, Boolean> apply,
                            Consumer<T> changed) {
        super(name, tooltip);

        this.apply = apply;
        this.comboBox = Inputs.comboBox(options, defaultValue, defaultValue == null, value -> {
            changed.accept(value);
            dirty = true;
            fireFieldChanged();
        });
    }

    @Override
    public JComponent getInputComponent() {
        return comboBox;
    }

    @SuppressWarnings("unchecked")
    @Override
    public boolean apply() {
        T value = (T) comboBox.getSelectedItem();
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