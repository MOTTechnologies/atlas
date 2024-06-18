package com.github.manevolent.atlas.ui.settings.field;

import com.github.manevolent.atlas.settings.BooleanSetting;
import com.github.manevolent.atlas.settings.Settings;
import com.github.manevolent.atlas.ui.util.Inputs;

import javax.swing.*;
import java.util.function.Consumer;
import java.util.function.Function;

public class CheckboxSettingField extends AbstractSettingField {
    private final Function<Boolean, Boolean> apply;
    private final JCheckBox checkBox;

    private boolean dirty;

    public CheckboxSettingField(String name,
                                String tooltip,
                                boolean defaultValue,
                                Function<Boolean, Boolean> apply,
                                Consumer<Boolean> changed) {
        super(name, tooltip);

        this.apply = apply;
        this.checkBox = Inputs.checkbox(name, defaultValue, (checked) -> {
            changed.accept(checked);
            dirty = true;
            fireFieldChanged();
        });
    }

    public CheckboxSettingField(String name,
                                String tooltip,
                                BooleanSetting setting) {
        this(name, tooltip,
                setting.get(),
                appliedValue -> {
                    setting.set(appliedValue);
                    return true;
                },
                changed -> { });
    }

    @Override
    public JComponent getInputComponent() {
        return checkBox;
    }

    @Override
    public boolean apply() {
        boolean value = checkBox.isSelected();
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