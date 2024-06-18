package com.github.manevolent.atlas;

import com.github.manevolent.atlas.logic.TableExecution;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class SubaruDITableMatchTest_LHBKC40M00G extends SubaruDITableMatchTest {
    private static final String projectFile = "projects/Subaru/WRX/USDM_VB_MT";
    private static final String calibrationName_a = "LHBHB10B00G";
    private static final String calibrationName_b = "LHBKC40M00G";

    public SubaruDITableMatchTest_LHBKC40M00G() {
        super(projectFile, calibrationName_a, calibrationName_b);
    }

    @Test
    public void test_boost_target_main() throws IOException {
        TableExecution matchedExecution = matchExecution(0x002f439e);
        assertEquals(0x00146920, matchedExecution.getDataOffset());
    }
}
