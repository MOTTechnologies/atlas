package com.github.manevolent.atlas.ui.settings;

import com.github.manevolent.atlas.math.InterpolationType;
import com.github.manevolent.atlas.settings.Settings;
import com.github.manevolent.atlas.ui.Editor;
import com.github.manevolent.atlas.ui.component.Window;
import com.github.manevolent.atlas.ui.component.table.TableComparer;
import com.github.manevolent.atlas.ui.component.table.TableEditor;
import com.github.manevolent.atlas.ui.settings.field.*;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import java.awt.*;
import java.util.List;

public class TableEditorSettingPage extends BasicSettingPage {
    private final Editor editor;

    public TableEditorSettingPage(Editor parent) {
        super(parent, CarbonIcons.DATA_TABLE, "Table Editor");
        this.editor = parent;
    }

    @Override
    protected List<SettingField> createFields() {
        return List.of(
                new CheckboxSettingField(
                        "Show 3D View", "Show the 3D visualization in the table editor",
                        Settings.TABLE_EDITOR_3D_VIEW
                ),
                new CheckboxSettingField(
                        "Show Stacked View", "Show the stacked visualization in the table editor",
                        Settings.TABLE_EDITOR_STACKED_VIEW
                ),
                new CheckboxSettingField(
                        "Live Axis Data", "Poll the vehicle for axis values",
                        Settings.TABLE_EDITOR_LIVE
                ),
                new CheckboxSettingField(
                        "Axis-aware Interpolation", "Weigh axis values when interpolate cells",
                        Settings.TABLE_EDITOR_AXIS_AWARE_INTERP
                ),
                new EnumSettingField<>(
                        "Interpolation Type", "Select the function to use when interpolating table values",
                        InterpolationType.class,
                        Settings.TABLE_EDITOR_INTERP_TYPE
                ),
                new IntegerSettingField(
                        "Font Size", "Table area font size",
                        1, 48,
                        Settings.TABLE_EDITOR_FONT_SIZE
                )
        );
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
