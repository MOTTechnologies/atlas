package com.github.manevolent.atlas.util;

import com.github.manevolent.atlas.ghidra.AtlasGhidraApplicationLayout;
import com.github.manevolent.atlas.ghidra.AtlasLogger;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.util.Msg;
import org.junit.jupiter.api.BeforeAll;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicBoolean;

public class GhidraHelper {

    private static final AtomicBoolean ghidraInitialized = new AtomicBoolean();
    public static void initializeGhidra() throws IOException {
        if (!ghidraInitialized.getAndSet(true)) {
            Application.initializeApplication(new AtlasGhidraApplicationLayout(), new ApplicationConfiguration());
            Msg.setErrorLogger(new AtlasLogger());
        }
    }

}
