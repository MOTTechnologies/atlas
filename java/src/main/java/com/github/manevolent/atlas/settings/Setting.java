package com.github.manevolent.atlas.settings;

import com.github.manevolent.atlas.math.InterpolationType;

import java.util.Arrays;
import java.util.Optional;
import java.util.stream.Collectors;

public class Setting<V, T extends SettingValue<V>> {
    public static <V, R extends SettingValue<V>> Setting<V, R> setting(Class<R> clazz, String name, V defaultValue) {
        return new Setting<V, R>(clazz, name, defaultValue);
    }

    public static <V, R extends SettingValue<V>> Setting<V, R> setting(Class<R> clazz, String name) {
        return new Setting<>(clazz, name, null);
    }

    public static StringSetting string(String name) {
        return new StringSetting(name);
    }

    public static <E extends Enum<E>> StringSetting enumValue(String name, E defaultValue) {
        return new StringSetting(name, defaultValue.name());
    }

    public static StringSetting string(String name, String defaultValue) {
        return new StringSetting(name, defaultValue);
    }

    public static IntegerSetting integer(String name, int defaultValue) {
        return new IntegerSetting(name, defaultValue);
    }

    public static IntegerSetting integer(String name) {
        return new IntegerSetting(name);
    }

    public static BooleanSetting bool(String name, boolean defaultValue) {
        return new BooleanSetting(name, defaultValue);
    }

    public static BooleanSetting bool(String name) {
        return new BooleanSetting(name);
    }

    private final String name;
    private final Class<T> valueClass;
    private final V defaultValue;

    public <C extends Class<T>> Setting(C valueClass, String name, V defaultValue) {
        this.name = name;
        this.valueClass = valueClass;
        this.defaultValue = defaultValue;
    }

    public <C extends Class<T>> Setting(C valueClass, V defaultValue, Object... nameParts) {
        this.defaultValue = defaultValue;
        this.name = Arrays.stream(nameParts).map(Object::toString).collect(Collectors.joining("."));
        this.valueClass = valueClass;
    }

    public V get() {
        return Settings.get(this);
    }

    public Optional<V> getOptional() {
        return Settings.getOptional(this);
    }

    public void set(V value) {
        Settings.set(this, value);
    }

    public void reset() {
        set(getDefaultValue());
    }

    public String getName() {
        return name;
    }

    public T getValueType() {
        try {
            return valueClass.getDeclaredConstructor().newInstance();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public V getDefaultValue() {
        return defaultValue;
    }

}
