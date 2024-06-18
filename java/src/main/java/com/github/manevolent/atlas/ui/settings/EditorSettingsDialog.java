package com.github.manevolent.atlas.ui.settings;

import com.github.manevolent.atlas.ui.Editor;

import org.kordamp.ikonli.carbonicons.CarbonIcons;

import java.util.List;

public class EditorSettingsDialog extends SettingsDialog<Editor> {
    public EditorSettingsDialog(Editor object) {
        super(CarbonIcons.SETTINGS, "Settings", object, object);
    }

    @Override
    protected List<SettingPage> createPages() {
        return List.of(
                new GeneralSettingPage(getSettingObject()),
                new UnitSettingPage(getSettingObject()),
                new DatalogSettingPage(getSettingObject()),
                new TableEditorSettingPage(getSettingObject()),
                new GraphEditorSettingPage(getSettingObject())
        );
    }
}
