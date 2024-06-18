package com.github.manevolent.atlas.ui.behavior;

public enum ChangeType {
    ADDED(true),
    MODIFIED(false),
    REMOVED(true);

    private final boolean listChanged;

    ChangeType(boolean listChanged) {
        this.listChanged = listChanged;
    }

    public boolean isListChange() {
        return listChanged;
    }
}
