package com.github.manevolent.atlas.ui.settings;

import com.github.manevolent.atlas.settings.Settings;
import com.github.manevolent.atlas.ui.settings.field.CheckboxSettingField;
import com.github.manevolent.atlas.ui.settings.field.SettingField;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import java.awt.*;
import java.util.List;

public class GeneralSettingPage extends BasicSettingPage {
    public GeneralSettingPage(Frame parent) {
        super(parent, CarbonIcons.SETTINGS, "General");
    }

    @Override
    protected java.util.List<SettingField> createFields() {
        return List.of(
                new CheckboxSettingField(
                        "Maximize New Windows", "Automatically maximize newly opened windows in the editor area.",
                        Settings.OPEN_WINDOWS_MAXIMIZED
                ),

                new CheckboxSettingField(
                        "Auto-connect", "Automatically connect to the vehicle when the default J2534 device is found.",
                        Settings.AUTO_CONNECT
                ),

                new CheckboxSettingField(
                        "Always open selected item", "Automatically select the focused Table, Format, etc. in the Project Tree.",
                        Settings.AUTO_SELECT_ITEM
                )
        );
    }
}
