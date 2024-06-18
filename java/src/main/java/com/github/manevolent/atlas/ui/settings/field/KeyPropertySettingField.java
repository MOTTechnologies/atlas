package com.github.manevolent.atlas.ui.settings.field;

import com.github.manevolent.atlas.model.KeyProperty;
import com.github.manevolent.atlas.model.KeySet;
import com.github.manevolent.atlas.ui.component.field.KeyField;

import javax.swing.*;
import java.awt.*;

public class KeyPropertySettingField extends AbstractSettingField {
    private final Frame parent;
    private final KeySet keySet;
    private final String key;

    private KeyProperty property;
    private boolean dirty;

    public KeyPropertySettingField(Frame parent, KeySet keySet,
                                   String key, String name, String tooltip) {
        super(name, tooltip);

        this.parent = parent;
        this.keySet = keySet;
        this.key = key;

        this.property = keySet.getProperty(key, KeyProperty.class);

        if (property != null) {
            // Clone so applying actually has a purpose
            property = property.copy();
        }
    }

    @Override
    public JComponent getInputComponent() {
        return new KeyField(parent, property, getTooltip(), (newValue) -> {
            property = newValue;
            dirty = true;
            fireFieldChanged();
        });
    }

    @Override
    public boolean apply() {
        keySet.addProperty(key, property);
        dirty = false;
        return true;
    }

    @Override
    public boolean isDirty() {
        return dirty;
    }
}
