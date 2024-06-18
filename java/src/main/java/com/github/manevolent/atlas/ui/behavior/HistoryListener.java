package com.github.manevolent.atlas.ui.behavior;

public interface HistoryListener<T extends Action> {

    default void onRemembered(T action) {}

    default void onUndoStarted(T action) {}

    default void onUndoCompleted(T action) {}

    default void onRedoStarted(T action) {}

    default void onRedoCompleted(T action) {}

}
