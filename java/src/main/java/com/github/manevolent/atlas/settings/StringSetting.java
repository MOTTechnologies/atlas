package com.github.manevolent.atlas.settings;

import com.google.gson.JsonElement;
import com.google.gson.JsonPrimitive;

import java.util.Arrays;

public class StringSetting extends Setting<String, StringSetting.Value> {
    public StringSetting(String defaultValue, Object... nameParts) {
        super(Value.class, defaultValue, nameParts);
    }

    public <C extends Class<Value>> StringSetting(String name, String defaultValue) {
        super(Value.class, name, defaultValue);
    }

    public <C extends Class<Value>> StringSetting(String name) {
        super(Value.class, name, (String) null);
    }

    public <E extends Enum<E>> E getAsEnum(Class<E> enumClass) {
        String value = get();
        return Arrays.stream(enumClass.getEnumConstants()).filter(x -> x.name().equals(value)).findFirst().orElse(null);
    }

    public <E extends Enum<E>> void setAsEnum(E value) {
        set(value.name());
    }

    public static class Value implements SettingValue<String> {
        @Override
        public String fromJson(JsonElement element) {
            return element.getAsString();
        }

        @Override
        public JsonElement toJson(String value) {
            return new JsonPrimitive(value);
        }
    }
}
