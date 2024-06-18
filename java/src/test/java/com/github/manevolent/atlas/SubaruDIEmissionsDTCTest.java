package com.github.manevolent.atlas;

import com.github.manevolent.atlas.logic.OS;
import com.github.manevolent.atlas.logic.SupportedDTC;
import com.github.manevolent.atlas.model.Calibration;
import com.github.manevolent.atlas.model.DTC;
import com.github.manevolent.atlas.model.DTCSystem;
import com.github.manevolent.atlas.model.Project;
import com.github.manevolent.atlas.model.storage.ProjectStorage;
import com.github.manevolent.atlas.model.storage.ProjectStorageType;
import com.github.manevolent.atlas.util.GhidraHelper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class SubaruDIEmissionsDTCTest {
    private static final String projectFile = "projects/Subaru/WRX/USDM_VB_MT";

    private static final Set<DTC> dtcs = new HashSet<>();
    static {
        dtcs.add(DTC.getDTC(DTCSystem.POWERTRAIN, 0x0420)); // Catalyst
    }

    public Project loadProject() throws IOException {
        ProjectStorage storage = ProjectStorageType.FOLDER.getStorageFactory().createStorage();
        return storage.load(new File(projectFile));
    }

    @BeforeAll
    public static void initializeGhidra() throws IOException {
        GhidraHelper.initializeGhidra();
    }

    @Test
    public void testEmissionsControlledDTCs() throws IOException {
        Project project = loadProject();
        for (Calibration calibration : project.getCalibrations()) {
            if (calibration.isConfidential()) {
                continue;
            }

            List<SupportedDTC> supportedDTCList;

            OS os;
            try {
                os = calibration.getOS();
            } catch (Exception ex) {
                continue;
            }

            try {
                supportedDTCList = os.getSupportedDTC();
            } catch (Exception ex) {
                ex.printStackTrace();
                continue;
            }

            for (DTC dtc : dtcs) {
                boolean anyEnabled = false;
                for (SupportedDTC emissionsDTC : supportedDTCList) {
                    if (emissionsDTC.getDTC() == dtc) {
                        anyEnabled = emissionsDTC.isEnabled();
                    }
                    if (anyEnabled) {
                        break;
                    }
                }
                assertTrue(anyEnabled, "Emissions DTC not enabled in " + calibration.getName() + ": " + dtc.getName());
            }
        }
    }

}
