package com.github.manevolent.atlas;

import com.github.manevolent.atlas.logic.*;
import com.github.manevolent.atlas.model.Calibration;
import com.github.manevolent.atlas.model.Project;
import com.github.manevolent.atlas.model.Table;
import com.github.manevolent.atlas.model.storage.ProjectStorage;
import com.github.manevolent.atlas.model.storage.ProjectStorageType;
import com.github.manevolent.atlas.ui.behavior.ProgressListener;
import com.github.manevolent.atlas.util.GhidraHelper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;

import java.io.File;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public abstract class SubaruDITableMatchTest {
    private final String projectFile;
    private final String calibrationName_source;
    private final String calibrationName_target;

    private OS source_os;
    private OS target_os;

    private List<TableExecution> source_executions;

    protected SubaruDITableMatchTest(String projectFile, String calibrationName_source, String calibrationName_target) {
        this.projectFile = projectFile;
        this.calibrationName_source = calibrationName_source;
        this.calibrationName_target = calibrationName_target;
    }

    @BeforeAll
    public void initializeGhidra() throws IOException {
        GhidraHelper.initializeGhidra();
    }

    @BeforeAll
    public void loadModel() throws IOException {
        source_os = loadSourceOS();
        target_os = loadTargetOS();

        source_executions = source_os.getExecutions(ProgressListener.DUMMY);
    }

    public Project loadProject() throws IOException {
        ProjectStorage storage = ProjectStorageType.FOLDER.getStorageFactory().createStorage();
        return storage.load(new File(projectFile));
    }

    public Calibration loadSourceCalibration() throws IOException {
        return loadProject().getCalibrations().stream()
                .filter(c -> c.getName().equals(calibrationName_source))
                .findFirst().orElseThrow(() -> new AssertionError(calibrationName_source));
    }

    public OS loadSourceOS() throws IOException {
        return loadSourceCalibration().getOS();
    }

    public Calibration loadTargetCalibration() throws IOException {
        return loadProject().getCalibrations().stream()
                .filter(c -> c.getName().equals(calibrationName_target))
                .findFirst().orElseThrow(() -> new AssertionError(calibrationName_target));
    }

    public OS loadTargetOS() throws IOException {
        return loadTargetCalibration().getOS();
    }

    public TableExecution matchExecution(long targetExecution) throws IOException {
        TableExecution targetExectuon = target_os.inspectCode(targetExecution);

        Table targetTable = targetExectuon.createTable(target_os.getCalibration());
        TablePlan b_plan = targetExectuon.getFunction().inspect();
        TableStructure b_structure = b_plan.getStructure(targetExectuon);
        Map<TableExecution, Float> scores_type_1 = new LinkedHashMap<>();
        Map<TableExecution, Float> scores_type_2 = new LinkedHashMap<>();
        TableComparer comparer = source_os.createComparer();
        for (TableExecution sourceExecution : source_executions) {
            if (sourceExecution.getFunction().getDimensions() !=
                    targetExectuon.getFunction().getDimensions()) {
                continue;
            }

            float score_type_1 = comparer.compareCode(sourceExecution, targetExectuon);
            if (score_type_1 > 0.75f) {
                scores_type_1.put(sourceExecution, score_type_1);
                continue;
            }

            TablePlan source_plan;

            try {
                source_plan = sourceExecution.getFunction().inspect();
            } catch (Exception ex) {
                continue;
            }

            TableStructure sourceStructure = source_plan.getStructure(sourceExecution);

            if (!sourceStructure.getAxes().stream().allMatch(axis ->
                    sourceStructure.getSeriesLength(axis) == b_structure.getSeriesLength(axis))) {
                continue;
            }

            Table sourceTable = sourceStructure.createTable(source_os.getCalibration());
            float score_type_2 = targetTable.compareTo(target_os.getCalibration(),
                    sourceTable, source_os.getCalibration());
            scores_type_2.put(sourceExecution, score_type_2);
        }

        TableExecution matched_1 = scores_type_1.entrySet().stream().max(Map.Entry.comparingByValue())
                .map(Map.Entry::getKey)
                .stream().findFirst().orElse(null);

        if (matched_1 != null) {
            return matched_1;
        }

        TableExecution matched_2 = scores_type_2.entrySet().stream().min(Map.Entry.comparingByValue())
                .map(Map.Entry::getKey)
                .stream().findFirst().orElse(null);

        if (matched_2 != null) {
            return matched_2;
        }

        throw new AssertionError("Failed to match table");
    }
}
