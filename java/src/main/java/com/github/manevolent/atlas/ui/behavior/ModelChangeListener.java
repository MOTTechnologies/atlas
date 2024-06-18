package com.github.manevolent.atlas.ui.behavior;

public interface ModelChangeListener {

    default void onModelChanged(Model model, ChangeType changeType) { }

}
