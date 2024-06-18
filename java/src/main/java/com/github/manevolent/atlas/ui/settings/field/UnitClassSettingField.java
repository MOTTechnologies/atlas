package com.github.manevolent.atlas.ui.settings.field;

import com.github.manevolent.atlas.model.Unit;
import com.github.manevolent.atlas.model.UnitClass;
import com.github.manevolent.atlas.settings.Settings;
import com.github.manevolent.atlas.ui.util.Inputs;

import javax.swing.*;
import java.util.Collection;
import java.util.function.Consumer;
import java.util.function.Function;

public class UnitClassSettingField extends AbstractSettingField {
    private final UnitClass unitClass;
    private final JComboBox<Unit> comboBox;

    private boolean dirty;

    public UnitClassSettingField(UnitClass unitClass) {
        super(unitClass.getName(), null);

        this.unitClass = unitClass;

        this.comboBox = Inputs.comboBox(unitClass.getUnits(), Settings.getPreferredUnit(unitClass), false, value -> {
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
        Unit value = (Unit) comboBox.getSelectedItem();
        if (dirty) {
            Settings.setPreferredUnit(unitClass, value);
        }
        dirty = false;
        return true;
    }

    @Override
    public boolean isDirty() {
        return dirty;
    }
}