package com.github.manevolent.atlas.ui.settings;

import com.github.manevolent.atlas.model.UnitClass;
import com.github.manevolent.atlas.settings.Settings;
import com.github.manevolent.atlas.ui.Editor;
import com.github.manevolent.atlas.ui.component.Window;
import com.github.manevolent.atlas.ui.component.table.TableComparer;
import com.github.manevolent.atlas.ui.component.table.TableEditor;
import com.github.manevolent.atlas.ui.settings.field.CheckboxSettingField;
import com.github.manevolent.atlas.ui.settings.field.SettingField;
import com.github.manevolent.atlas.ui.settings.field.UnitClassSettingField;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import java.awt.*;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.List;

public class UnitSettingPage extends BasicSettingPage {
    private final Editor editor;

    public UnitSettingPage(Editor parent) {
        super(parent, CarbonIcons.RULER, "Units");

        this.editor = parent;
    }

    @Override
    protected List<SettingField> createFields() {
        List<UnitClass> classes = EnumSet.allOf(UnitClass.class).stream()
                .filter(unitClass -> unitClass.getUnits().size() > 1)
                .sorted(Comparator.comparing(UnitClass::getName))
                .toList();

        return classes.stream()
                .map(unitClass -> (SettingField) new UnitClassSettingField(unitClass))
                .toList();
    }

    @Override
    public boolean apply() {
        if (super.apply()) {
            editor.getOpenWindows(TableEditor.class).forEach(Window::reload);
            editor.getOpenWindows(TableComparer.class).forEach(Window::reload);
            return true;
        } else {
            return false;
        }
    }
}
