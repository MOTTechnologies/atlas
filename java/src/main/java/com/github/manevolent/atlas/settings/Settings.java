package com.github.manevolent.atlas.settings;

import com.github.manevolent.atlas.ApplicationMetadata;
import com.github.manevolent.atlas.logging.Log;
import com.github.manevolent.atlas.math.InterpolationType;
import com.github.manevolent.atlas.model.Unit;
import com.github.manevolent.atlas.model.UnitClass;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.stream.JsonWriter;

import java.io.*;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.logging.Level;

public final class Settings {
    private static final String SETTINGS_FOLDER_NAME = "." + ApplicationMetadata.getName().toLowerCase();

    public static final StringSetting DEVICE_PROVIDER = Setting.string("can.device.provider");
    public static final StringSetting LAST_OPENED_PROJECT = Setting.string("editor.project.last_opened_file");
    public static final BooleanSetting AUTO_SELECT_ITEM = Setting.bool("editor.projectTree.autoSelectItem", true);

    public static final BooleanSetting OPEN_WINDOWS_MAXIMIZED = Setting.bool("editor.openMaximized", true);

    public static final BooleanSetting AUTO_CONNECT = Setting.bool("editor.autoConnect", false);

    public static final IntegerSetting DATALOG_FREQUENCY = Setting.integer("datalog.frequency", 30);
    public static final IntegerSetting DATALOG_DEFAULT_WIDTH = Setting.integer("datalog.defaultWith", 10);
    public static final IntegerSetting DATALOG_MAXIMUM_HISTORY = Setting.integer("datalog.maxHistory", 60);

    public static final BooleanSetting TABLE_EDITOR_3D_VIEW = Setting.bool("tableEditor.show3D", true);
    public static final BooleanSetting TABLE_EDITOR_STACKED_VIEW = Setting.bool("tableEditor.showStacked", true);
    public static final BooleanSetting TABLE_EDITOR_LIVE = Setting.bool("tableEditor.live", true);
    public static final StringSetting TABLE_EDITOR_INTERP_TYPE = Setting.enumValue("tableEditor.interpType",
            InterpolationType.LINEAR);
    public static final BooleanSetting TABLE_EDITOR_AXIS_AWARE_INTERP = Setting.bool("tableEditor.axisAwareInterp", true);
    public static final IntegerSetting TABLE_EDITOR_FONT_SIZE = Setting.integer("tableEditor.fontSize", 12);

    public static final BooleanSetting GRAPH_EDITOR_LIVE = Setting.bool("graphEditor.live", true);
    public static final BooleanSetting GRAPH_EDITOR_DRAW_GRID_LINES = Setting.bool("graphEditor.drawGridLines", true);

    public static final Map<UnitClass, StringSetting> UNIT_SETTINGS = new HashMap<>();
    static {
        for (UnitClass unitClass : UnitClass.values()) {
            Unit defaultUnit = unitClass.getDefaultUnit();

            if (defaultUnit != null) {
                UNIT_SETTINGS.put(unitClass,
                        StringSetting.enumValue("editor.unit." + unitClass.name(), defaultUnit));
            }
        }
    }

    public static Unit getPreferredUnit(UnitClass unitClass) {
        StringSetting setting = UNIT_SETTINGS.get(unitClass);

        Unit preferred;
        if (setting != null) {
            preferred = setting.getAsEnum(Unit.class);
        } else {
            preferred = null;
        }

        if (preferred == null) {
            preferred = unitClass.getDefaultUnit();
        }

        return preferred;
    }

    public static void setPreferredUnit(UnitClass unitClass, Unit unit) {
        UNIT_SETTINGS.get(unitClass).setAsEnum(unit);
    }

    public static File getSettingsDirectory() {
        String home = System.getProperty("user.home");
        File homeDirectory = new File(home);
        File settingsDirectory = new File(homeDirectory.getPath() + File.separator + SETTINGS_FOLDER_NAME);
        settingsDirectory.mkdirs();
        return settingsDirectory;
    }

    private static Settings settings;

    public static Settings getAll() {
        if (settings == null) {
            settings = new Settings(getSettingsDirectory());
        }
        return settings;
    }

    public static <V, R extends SettingValue<V>, T extends Setting<V, R>> Optional<V> getOptional(T setting) {
        return Optional.ofNullable(get(setting));
    }

    public static <V, R extends SettingValue<V>, T extends Setting<V, R>> V get(T setting) {
        return getAll().getValue(setting);
    }

    public static <V, R extends SettingValue<V>, T extends Setting<V, R>> V get(T setting, V defaultValue) {
        V value = getAll().getValue(setting);

        if (value == null) {
            return defaultValue;
        } else {
            return value;
        }
    }

    public static <V, R extends SettingValue<V>, T extends Setting<V, R>> void set(T setting, V value) {
        getAll().setValue(setting, value);
    }

    private final File directory;
    private final File settingsFile;
    private final JsonObject settingsMap;

    private Settings(File directory) {
        this.directory = directory;
        this.settingsFile = new File(directory.getPath() + File.separator + "settings.json");
        this.settingsMap = load();
    }

    public JsonObject load() {
        if (settingsFile.exists()) {
            try {
                return JsonParser.parseReader(new FileReader(settingsFile)).getAsJsonObject();
            } catch (FileNotFoundException e) {
                Log.settings().log(Level.SEVERE, "Problem loading settings", e);
            }
        }

        return new JsonObject();
    }

    public void save() {
        try (FileWriter writer = new FileWriter(settingsFile)) {
            new Gson().toJson(settingsMap, new JsonWriter(writer));
            Log.settings().log(Level.FINE, "Saved settings to " + settingsFile.getPath() + ".");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private JsonElement getValueElement(String settingName) {
        return settingsMap.get(settingName);
    }

    public <V, R extends SettingValue<V>, T extends Setting<V, R>> V getValue(T setting) {
        R valueType = setting.getValueType();
        JsonElement valueElement = getValueElement(setting.getName());

        V value;

        if (valueElement == null || valueElement.isJsonNull()) {
            value = setting.getDefaultValue();

            if (value == null) {
                value = valueType.getDefault();
            }
        } else {
            value = valueType.fromJson(valueElement);
        }

        return value;
    }

    public <V, R extends SettingValue<V>, T extends Setting<V, R>> void setValue(T setting, V value) {
        R valueClass = setting.getValueType();
        JsonElement element = valueClass.toJson(value);
        settingsMap.add(setting.getName(), element);
        Log.settings().log(Level.FINE, "Set setting " + setting.getName() + " to \"" + value.toString() + "\".");
        save();
    }

}
