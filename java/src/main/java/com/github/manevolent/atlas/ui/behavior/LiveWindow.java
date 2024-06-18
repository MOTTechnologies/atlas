package com.github.manevolent.atlas.ui.behavior;

import com.github.manevolent.atlas.model.MemoryParameter;

import java.util.Set;

public interface LiveWindow {

    Set<MemoryParameter> getParameters();

    boolean isLive();

}
