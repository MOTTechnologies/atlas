package com.github.manevolent.atlas.logic;

import com.github.manevolent.atlas.model.DTC;

import javax.help.UnsupportedOperationException;
import java.io.IOException;

public abstract class AbstractSupportedDTC implements SupportedDTC {
    private final DTC dtc;

    protected AbstractSupportedDTC(DTC dtc) {
        this.dtc = dtc;
    }

    @Override
    public final DTC getDTC() {
        return dtc;
    }

    protected abstract void setEnabledUncontrolled(boolean enabled) throws IOException;

    @Override
    public final void setEnabled(boolean enabled) throws IOException {
        // DO NOT TAMPER, See DTC.java
        if (!enabled && dtc.isEmissionsRelated()) {
            throw new UnsupportedOperationException("Cannot disable emissions-controlled DTC");
        } else {
            setEnabledUncontrolled(enabled);
        }
    }

}
