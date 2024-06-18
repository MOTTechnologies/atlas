package com.github.manevolent.atlas.model;

import java.util.*;
import java.util.stream.Collectors;

public class KeySet extends AbstractAnchored implements Editable<KeySet>, Secured {
    private String name;
    private boolean active;
    private boolean confidential = true; // Make all key sets confidential by default
    private Map<String, ProjectProperty> properties = new LinkedHashMap<>();

    public KeySet() {
        properties = new LinkedHashMap<>();
    }

    public String getName() {
        return this.name;
    }

    public void setName(String newKeySetName) {
        this.name = newKeySetName;
    }

    public boolean isConfidential() {
        return confidential;
    }

    public void setConfidential(boolean confidential) {
        this.confidential = confidential;
    }

    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }

    public Map<String, ProjectProperty> getProperties() {
        return properties;
    }

    public void setProperties(Map<String, ProjectProperty> map) {
        this.properties = map;
    }

    public ProjectProperty getProperty(String name) {
        return properties.get(name);
    }

    @SuppressWarnings("unchecked")
    public <T extends ProjectProperty> T getProperty(String name, Class<T> clazz) {
        return (T) getProperty(name);
    }

    public void addProperty(String name, ProjectProperty property) {
        properties.put(name, property);
    }

    public void removeProperty(String name) {
        properties.remove(name);
    }

    public Collection<String> getPropertyNames() {
        return properties.keySet();
    }

    public Collection<ProjectProperty> getPropertyValues() {
        return properties.values();
    }

    public boolean hasProperty(String name) {
        return properties.containsKey(name);
    }

    public boolean hasProperty(ProjectProperty property) {
        return properties.containsValue(property);
    }

    private Map<String, ProjectProperty> copy(Map<String, ProjectProperty> other) {
        return other.entrySet().stream()
                .filter(entry -> entry.getValue() != null)
                .map(entry -> {
                    ProjectProperty value = entry.getValue();
                    value = value.copy();
                    return new AbstractMap.SimpleEntry<>(entry.getKey(), value);
                })
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    @Override
    public KeySet copy() {
        KeySet keySet = new KeySet();
        keySet.name = name;
        keySet.confidential = confidential;
        keySet.properties = Editable.copy(properties);
        return keySet;
    }

    @Override
    public void apply(KeySet other) {
        name = other.name;
        confidential = other.confidential;
        Editable.apply(properties, other.properties);
    }

    @Override
    public String toString() {
        return getName();
    }
}
