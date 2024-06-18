package com.github.manevolent.atlas.ui.settings;

import com.github.manevolent.atlas.settings.Setting;
import com.github.manevolent.atlas.settings.Settings;
import com.github.manevolent.atlas.ui.settings.field.IntegerSettingField;
import com.github.manevolent.atlas.ui.settings.field.SettingField;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import java.awt.*;
import java.util.List;

public class DatalogSettingPage extends BasicSettingPage {
    public DatalogSettingPage(Frame parent) {
        super(parent, CarbonIcons.CHART_AVERAGE, "Data Logging");
    }

    @Override
    protected List<SettingField> createFields() {
        return List.of(
                new IntegerSettingField(
                        "Polling Frequency (Hz)", "The datalog/gauge datapoint polling frequency, in hertz",
                        1, 1000,
                        Settings.DATALOG_FREQUENCY
                ),
                new IntegerSettingField(
                        "Default Width (sec.)", "The default datalog window width ('T'), in seconds",
                        1, 60 * 10,
                        Settings.DATALOG_DEFAULT_WIDTH
                ),
                new IntegerSettingField(
                        "Maximum History (sec.)", "The maximum datalog history kept, in seconds",
                        1, 60 * 60,
                        Settings.DATALOG_MAXIMUM_HISTORY
                )
        );
    }
}
