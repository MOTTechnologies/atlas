package com.github.manevolent.atlas.ui.settings.field;

import com.github.manevolent.atlas.model.Color;
import com.github.manevolent.atlas.settings.BooleanSetting;
import com.github.manevolent.atlas.ui.component.field.ColorField;
import com.github.manevolent.atlas.ui.util.Inputs;

import javax.swing.*;
import java.util.function.Consumer;
import java.util.function.Function;

public class ColorSettingField extends AbstractSettingField {
    private final Function<Color, Boolean> apply;
    private final ColorField colorField;

    private boolean dirty;

    public ColorSettingField(String name,
                             String tooltip,
                             Color defaultValue,
                             Function<Color, Boolean> apply,
                             Consumer<Color> changed) {
        super(name, tooltip);

        this.apply = apply;
        this.colorField = new ColorField(null, defaultValue, (checked) -> {
            changed.accept(checked);
            dirty = true;
            fireFieldChanged();
        });
    }

    @Override
    public JComponent getInputComponent() {
        return colorField;
    }

    @Override
    public boolean apply() {
        Color value = colorField.getColor();
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