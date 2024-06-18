package com.github.manevolent.atlas.settings;

import com.google.gson.JsonElement;
import com.google.gson.JsonPrimitive;

public class BooleanSetting extends Setting<Boolean, BooleanSetting.Value> {
    public BooleanSetting(boolean defaultValue, Object... nameParts) {
        super(BooleanSetting.Value.class, defaultValue, nameParts);
    }

    public <C extends Class<BooleanSetting.Value>> BooleanSetting(String name, boolean defaultValue) {
        super(BooleanSetting.Value.class, name, defaultValue);
    }

    public <C extends Class<BooleanSetting.Value>> BooleanSetting(String name) {
        super(BooleanSetting.Value.class, name, null);
    }

    public static class Value implements SettingValue<Boolean> {
        @Override
        public Boolean fromJson(JsonElement element) {
            return element.getAsBoolean();
        }

        @Override
        public JsonElement toJson(Boolean value) {
            return new JsonPrimitive(value);
        }
    }
}
