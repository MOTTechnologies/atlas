package com.github.manevolent.atlas.logic;

import com.github.manevolent.atlas.model.DTC;

import java.io.IOException;

public interface SupportedDTC {

    DTC getDTC();

    boolean isEnabled() throws IOException;

    void setEnabled(boolean enabled) throws IOException;

}
