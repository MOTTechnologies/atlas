package com.github.manevolent.atlas.ui.settings;

import com.github.manevolent.atlas.ui.settings.field.SettingField;
import org.kordamp.ikonli.Ikon;

import java.awt.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

public class DefaultSettingPage extends BasicSettingPage {
    private final List<SettingField> elements;

    public DefaultSettingPage(Frame parent, Ikon icon, String name, List<SettingField> elements) {
        super(parent, icon, name);
        this.elements = elements;
    }

    public DefaultSettingPage(Frame parent, Ikon icon, String name, SettingField... elements) {
        this(parent, icon, name, Arrays.asList(elements));
    }

    @Override
    protected List<SettingField> createFields() {
        return elements;
    }
}
