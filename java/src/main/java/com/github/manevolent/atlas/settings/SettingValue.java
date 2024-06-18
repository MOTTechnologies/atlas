package com.github.manevolent.atlas.settings;

import com.google.gson.JsonElement;

public interface SettingValue<T> {

    /**
     * Gets the default value for this setting type if no value is present. This is not setting-specific, but instead
     * is type-specific (i.e. the default value for an enum).
     * @return default value, or null.
     */
    default T getDefault() {
        return (T) null;
    }

    T fromJson(JsonElement element);

    JsonElement toJson(T value);

}
