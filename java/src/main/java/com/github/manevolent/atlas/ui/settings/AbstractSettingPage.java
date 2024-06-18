package com.github.manevolent.atlas.ui.settings;

import com.github.manevolent.atlas.ui.settings.field.FieldChangeListener;
import com.github.manevolent.atlas.ui.settings.field.SettingField;
import org.kordamp.ikonli.Ikon;

import java.util.LinkedList;
import java.util.List;

public abstract class AbstractSettingPage implements SettingPage {
    private final Ikon icon;
    private final String name;
    private final List<FieldChangeListener> fieldChangeListeners = new LinkedList<>();

    protected AbstractSettingPage(Ikon icon, String name) {
        this.icon = icon;
        this.name = name;
    }

    @Override
    public Ikon getIcon() {
        return icon;
    }

    @Override
    public String getName() {
        return name;
    }

    protected void fireFieldChanged(SettingField changed) {
        this.fieldChangeListeners.forEach(listener -> listener.onFieldChanged(changed));
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
