package com.github.manevolent.atlas;

import com.github.manevolent.atlas.ghidra.AtlasGhidraApplicationLayout;
import com.github.manevolent.atlas.ghidra.AtlasLogger;
import com.github.manevolent.atlas.logic.*;
import com.github.manevolent.atlas.model.Calibration;
import com.github.manevolent.atlas.model.Project;
import com.github.manevolent.atlas.model.storage.ProjectStorage;
import com.github.manevolent.atlas.model.storage.ProjectStorageType;
import com.github.manevolent.atlas.util.GhidraHelper;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.util.Msg;
import org.junit.jupiter.api.BeforeAll;

import java.io.File;
import java.io.IOException;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;

public abstract class SubaruDITableTest {
    private final String projectFile;
    private final String calibrationName;

    protected SubaruDITableTest(String projectFile, String calibrationName) {
        this.projectFile = projectFile;
        this.calibrationName = calibrationName;
    }

    @BeforeAll
    public static void initializeGhidra() throws IOException {
        GhidraHelper.initializeGhidra();
    }

    public Project loadProject() throws IOException {
        ProjectStorage storage = ProjectStorageType.FOLDER.getStorageFactory().createStorage();
        return storage.load(new File(projectFile));
    }

    public Calibration loadCalibration() throws IOException {
        return loadProject().getCalibrations().stream()
                .filter(c -> c.getName().equals(calibrationName))
                .findFirst().orElseThrow(() -> new AssertionError(calibrationName));
    }

    public OS loadOS() throws IOException {
        return loadCalibration().getOS();
    }

    public TableStructure loadTableStructure(long offset) throws IOException {
        OS os = loadOS();
        TableExecution execution = os.inspectCode(offset);

        if (execution == null) {
            throw new IllegalArgumentException("No table execution found at 0x" + Long.toHexString(offset));
        }

        TableFunction function = execution.getFunction();
        TablePlan layout = function.inspect();

        assertEquals(layout.getDimensions(), function.getDimensions());
        return layout.getStructure(execution);
    }
}
