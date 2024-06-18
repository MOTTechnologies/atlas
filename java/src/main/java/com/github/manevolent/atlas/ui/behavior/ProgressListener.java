package com.github.manevolent.atlas.ui.behavior;

public interface ProgressListener {

    ProgressListener DUMMY = (m, p) -> { };

    void updateProgress(String message, float progress);

}
