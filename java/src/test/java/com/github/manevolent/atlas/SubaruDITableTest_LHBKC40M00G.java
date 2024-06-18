package com.github.manevolent.atlas;

import com.github.manevolent.atlas.connection.subaru.SubaruDIPlatform;
import com.github.manevolent.atlas.ghidra.AtlasGhidraApplicationLayout;
import com.github.manevolent.atlas.ghidra.AtlasLogger;
import com.github.manevolent.atlas.logic.*;
import com.github.manevolent.atlas.model.Calibration;
import com.github.manevolent.atlas.model.Checksum;
import com.github.manevolent.atlas.model.DataFormat;
import com.github.manevolent.atlas.model.Project;
import com.github.manevolent.atlas.model.storage.ProjectStorage;
import com.github.manevolent.atlas.model.storage.ProjectStorageType;
import com.github.manevolent.atlas.ui.behavior.ProgressListener;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.util.Msg;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.util.List;

import static com.github.manevolent.atlas.model.Axis.X;
import static com.github.manevolent.atlas.model.Axis.Y;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class SubaruDITableTest_LHBKC40M00G extends SubaruDITableTest {
    private static final String projectFile = "projects/Subaru/WRX/USDM_VB_MT";
    private static final String calibrationName = "LHBKC40M00G";

    public SubaruDITableTest_LHBKC40M00G() {
        super(projectFile, calibrationName);
    }

    /**
     * This test is important. This ensures the OEM calibration file isn't corrupt.
     * @throws IOException
     */
    @Test
    public void test_checksum() throws IOException {
        Calibration calibration = loadCalibration();
        Checksum checksum = SubaruDIPlatform.USDM_2023_WRX_MT.getChecksum(calibration);
        if (!checksum.validate(calibration)) {
            throw new AssertionError("Invalid checksum");
        }
    }

    @Test
    public void test_ign_primary_a() throws IOException {
        TableStructure structure = loadTableStructure(0x001c95f6);

        assertEquals(structure.getSeriesLength(X), 30);
        assertEquals(structure.getSeriesLength(Y), 22);

        assertEquals(structure.getDataFormat(X), DataFormat.USHORT);
        assertEquals(structure.getDataFormat(Y), DataFormat.USHORT);
    }

    @Test
    public void test_target_boost_a() throws IOException {
        TableStructure structure = loadTableStructure(0x002f439e);
    }
}
