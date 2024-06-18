package com.github.manevolent.atlas.ui.settings.field;

import java.util.LinkedList;
import java.util.List;

public abstract class AbstractSettingField implements SettingField {
    private final String name, tooltip;
    private final List<FieldChangeListener> fieldChangeListeners = new LinkedList<>();

    protected AbstractSettingField(String name, String tooltip) {
        this.name = name;
        this.tooltip = tooltip;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public String getTooltip() {
        return tooltip;
    }

    protected void fireFieldChanged() {
        this.fieldChangeListeners.forEach(listener -> listener.onFieldChanged(this));
    }

    @Override
    public void addChangeListener(FieldChangeListener listener) {
        this.fieldChangeListeners.add(listener);
    }

    @Override
    public void removeChangeListener(FieldChangeListener listener) {
        this.fieldChangeListeners.remove(listener);
    }
}
