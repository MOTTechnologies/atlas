package com.github.manevolent.atlas.settings;

import com.google.gson.JsonElement;
import com.google.gson.JsonPrimitive;

public class IntegerSetting extends Setting<Integer, IntegerSetting.Value> {
    public IntegerSetting(Object... nameParts) {
        super(IntegerSetting.Value.class, null, nameParts);
    }
    public IntegerSetting(int defaultValue, Object... nameParts) {
        super(IntegerSetting.Value.class, defaultValue, nameParts);
    }

    public <C extends Class<IntegerSetting.Value>> IntegerSetting(String name, int defaultValue) {
        super(IntegerSetting.Value.class, name, defaultValue);
    }

    public <C extends Class<IntegerSetting.Value>> IntegerSetting(String name) {
        super(IntegerSetting.Value.class, name, null);
    }

    public static class Value implements SettingValue<Integer> {
        @Override
        public Integer fromJson(JsonElement element) {
            return element.getAsInt();
        }

        @Override
        public JsonElement toJson(Integer value) {
            return new JsonPrimitive(value);
        }
    }
}
