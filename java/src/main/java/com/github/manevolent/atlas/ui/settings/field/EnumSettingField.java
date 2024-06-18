package com.github.manevolent.atlas.ui.settings.field;

import com.github.manevolent.atlas.connection.ConnectionType;
import com.github.manevolent.atlas.settings.StringSetting;
import com.github.manevolent.atlas.ui.util.Inputs;

import javax.swing.*;
import java.util.function.Consumer;
import java.util.function.Function;

public class EnumSettingField<E extends Enum<E>> extends AbstractSettingField {
    private final Function<E, Boolean> apply;
    private final JComboBox<E> comboBox;

    private boolean dirty;

    public EnumSettingField(String name,
                            String tooltip,
                            Class<E> type,
                            E defaultValue,
                            Function<E, Boolean> apply,
                            Consumer<E> changed) {
        super(name, tooltip);

        this.apply = apply;
        this.comboBox = Inputs.enumField(tooltip, type, defaultValue, value -> {
            changed.accept(value);
            dirty = true;
            fireFieldChanged();
        });
    }

    public EnumSettingField(String name,
                            String tooltip,
                            Class<E> type,
                            StringSetting enumSetting) {
        super(name, tooltip);

        this.apply = (v) -> {
            enumSetting.setAsEnum(v);
            return true;
        };

        this.comboBox = Inputs.enumField(tooltip, type, enumSetting.getAsEnum(type), value -> {
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
        E value = (E) comboBox.getSelectedItem();
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