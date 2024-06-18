package com.github.manevolent.atlas;

import com.github.manevolent.atlas.connection.subaru.SubaruDIPlatform;
import com.github.manevolent.atlas.ghidra.AtlasGhidraApplicationLayout;
import com.github.manevolent.atlas.ghidra.AtlasLogger;
import com.github.manevolent.atlas.logic.*;
import com.github.manevolent.atlas.model.*;
import com.github.manevolent.atlas.model.storage.ProjectStorage;
import com.github.manevolent.atlas.model.storage.ProjectStorageType;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.util.ErrorLogger;
import ghidra.util.Msg;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.util.stream.Collectors;

import static com.github.manevolent.atlas.model.Axis.X;
import static com.github.manevolent.atlas.model.Axis.Y;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class SubaruDITableTest_LHBHB10B00G extends SubaruDITableTest {
    private static final String projectFile = "projects/Subaru/WRX/USDM_VB_MT";
    private static final String calibrationName = "LHBHB10B00G";

    public SubaruDITableTest_LHBHB10B00G() {
        super(projectFile, calibrationName);
    }

    /**
     * This test is important. This ensures the OEM calibration file isn't corrupt.
     * @throws IOException
     */
    @Test
    public void test_checksum() throws IOException {
        Calibration calibration = loadCalibration();
        Checksum checksum = SubaruDIPlatform.USDM_2022_WRX_MT.getChecksum(calibration);
        checksum.validate(calibration);
        if (!checksum.validate(calibration)) {
            throw new AssertionError("Invalid checksum");
        }
    }

    @Test
    public void test_wastegate_table_a() throws IOException {
        TableStructure structure = loadTableStructure(0x002dc6bc);

        assertEquals(structure.getSeriesLength(X), 16);
        assertEquals(structure.getSeriesLength(Y), 18);

        assertEquals(structure.getDataFormat(X), DataFormat.UBYTE);
        assertEquals(structure.getDataFormat(Y), DataFormat.USHORT);
    }

    @Test
    public void test_wastegate_table_b() throws IOException {
        TableStructure structure = loadTableStructure(0x002dc69c);

        assertEquals(structure.getSeriesLength(X), 30);
        assertEquals(structure.getSeriesLength(Y), 18);

        assertEquals(structure.getDataFormat(X), DataFormat.USHORT);
        assertEquals(structure.getDataFormat(Y), DataFormat.USHORT);
    }

    @Test
    public void test_wastegate_table_c() throws IOException {
        TableStructure structure = loadTableStructure(0x002dc6dc);

        assertEquals(structure.getSeriesLength(X), 16);
        assertEquals(structure.getSeriesLength(Y), 18);

        assertEquals(structure.getDataFormat(X), DataFormat.USHORT);
        assertEquals(structure.getDataFormat(Y), DataFormat.USHORT);
    }

    @Test
    public void test_fuel_table_a() throws IOException {
        TableStructure structure = loadTableStructure(0x001a434c);

        assertEquals(structure.getSeriesLength(X), 30);
        assertEquals(structure.getSeriesLength(Y), 24);

        assertEquals(structure.getDataFormat(X), DataFormat.UBYTE);
        assertEquals(structure.getDataFormat(Y), DataFormat.USHORT);
    }

    @Test
    public void test_fuel_table_b() throws IOException {
        TableStructure structure = loadTableStructure(0x001a444e);
        assertEquals(structure.getSeriesLength(X), 16);
        assertEquals(structure.getDataFormat(X), DataFormat.UBYTE);
    }

    @Test
    public void test_dam_table_a() throws IOException {
        TableStructure structure = loadTableStructure(0x001ce7d4);

        assertEquals(structure.getSeriesLength(X), 30);
        assertEquals(structure.getSeriesLength(Y), 21);

        assertEquals(structure.getDataFormat(X), DataFormat.USHORT);
        assertEquals(structure.getDataFormat(Y), DataFormat.USHORT);
    }

    @Test
    public void test_ign_comp_shift_a() throws IOException {
        TableStructure structure = loadTableStructure(0x001c5c60);

        assertEquals(structure.getSeriesLength(X), 20);
        assertEquals(structure.getSeriesLength(Y), 6);

        assertEquals(structure.getDataFormat(X), DataFormat.USHORT);
        assertEquals(structure.getDataFormat(Y), DataFormat.UBYTE);
    }

    /**
     * Added this table because its data series was getting confused with one of its axis series
     */
    @Test
    public void test_problematic_a() throws IOException {
        TableStructure structure = loadTableStructure(0x0010857c);

        assertEquals(structure.getDataOffset(), 0x00011820L);

        assertEquals(structure.getSeriesLength(X), 20);
        assertEquals(structure.getSeriesLength(Y), 21);

        assertEquals(structure.getDataFormat(X), DataFormat.USHORT);
        assertEquals(structure.getDataFormat(Y), DataFormat.USHORT);
    }

    /**
     * Added this table because its data series format was getting misidentified as uint
     */
    @Test
    public void test_problematic_b() throws IOException {
        TableStructure structure = loadTableStructure(0x00192afe);

        assertEquals(structure.getDataFormat(), DataFormat.USHORT);

        assertEquals(structure.getSeriesLength(X), 26);
        assertEquals(structure.getSeriesLength(Y), 22);

        assertEquals(structure.getDataFormat(X), DataFormat.UBYTE);
        assertEquals(structure.getDataFormat(Y), DataFormat.USHORT);
    }

    /**
     * Added this table because its data series was getting confused with one of its axis series
     */
    @Test
    public void test_problematic_c() throws IOException {
        TableStructure structure = loadTableStructure(0x002dc418);
    }

    @Test
    public void test_boost_target_main() throws IOException {
        TableStructure structure = loadTableStructure(0x002dc4f0);

        assertEquals(structure.getDataFormat(), DataFormat.USHORT);

        assertEquals(structure.getSeriesLength(X), 36);
        assertEquals(structure.getSeriesLength(Y), 19);

        assertEquals(structure.getDataFormat(X), DataFormat.USHORT);
        assertEquals(structure.getDataFormat(Y), DataFormat.USHORT);
    }
}
