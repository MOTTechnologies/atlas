package com.github.manevolent.atlas.ui.util;

import com.github.manevolent.atlas.logic.*;
import com.github.manevolent.atlas.model.*;
import com.github.manevolent.atlas.ui.Editor;
import com.github.manevolent.atlas.ui.behavior.ChangeType;
import com.github.manevolent.atlas.ui.behavior.Model;
import com.github.manevolent.atlas.ui.component.calibration.*;
import com.github.manevolent.atlas.ui.component.tab.TreeTab;
import com.github.manevolent.atlas.ui.component.table.TableExplorer;
import com.github.manevolent.atlas.ui.dialog.BinaryInputDialog;
import com.github.manevolent.atlas.ui.dialog.MemoryAddressDialog;
import com.github.manevolent.atlas.ui.dialog.ProgressDialog;
import org.apache.commons.lang.exception.ExceptionUtils;
import org.kordamp.ikonli.carbonicons.CarbonIcons;
import org.kordamp.ikonli.fontawesome5.FontAwesomeSolid;

import javax.swing.*;
import java.io.IOException;
import java.util.*;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import static com.github.manevolent.atlas.ui.util.Inputs.showOptionDialog;

public class Tools {

    /**
     * Helper method to load an OS from the currently selected calibration.
     * @param editor Editor instance to load an OS from
     * @return OS instance.
     */
    private static OS loadOs(Editor editor) {
        Calibration calibration = editor.getCalibration();
        if (calibration == null) {
            Errors.show(editor, "Match tables failed", "No calibration is selected.");
            return null;
        }

        Variant variant = calibration.getVariant();
        OSType osType = variant.getOSType();
        if (osType == null) {
            Errors.show(editor, "Match tables failed", "The current variant \""
                    + variant.getName() + "\" does not have an OS specified.");
            return null;
        }

        OS os;
        try {
            os = osType.createOS(calibration);
        } catch (IOException e) {
            Errors.show(editor, "OS load failed", "Problem loading OS!", e);
            return null;
        }

        return os;
    }

    public static void findTable(Editor editor, Table table, Calibration calibration) {
        OS os = loadOs(editor);
        if (os == null) {
            return;
        }

        Series data = table.getData();
        editor.executeWithProgress("Searching for Table",
                "Searching for table " + table + " in " + editor.getCalibration() + "...",
                (progressDialog) -> {
                    TableStructure structure;
                    try {
                        structure = os.findTableStructures(progressDialog)
                                .stream()
                                .filter(s -> {
                                    long dataPointer;
                                    Map<Axis, Long> axes = new HashMap<>();
                                    dataPointer = s.getDataOffset();
                                    for (Axis axis : s.getAxes()) {
                                        axes.put(axis, s.getSeriesOffset(axis));
                                    }

                                    // Check the data address
                                    if (data.getAddress().getOffset(os.getVariant()) != dataPointer) {
                                        return false;
                                    }

                                    // Check all the axes
                                    if (table.getAllAxes().size() != axes.size()) {
                                        return false;
                                    } else {
                                        return axes.keySet().stream()
                                                .allMatch(axis -> axes.get(axis) == table.getSeries(axis)
                                                        .getAddress().getOffset(os.getVariant()));
                                    }
                                })
                                .findFirst()
                                .orElse(null);
                    } catch (Throwable ex) {
                        if (ExceptionUtils.getRootCause(ex) instanceof InterruptedException) {
                            return;
                        }

                        SwingUtilities.invokeLater(() -> {
                            Errors.show(editor, "Table search failed", "Problem searching for tables!", ex);
                        });

                        return;
                    } finally {
                        progressDialog.dispose();
                    }

                    if (structure != null) {
                        String axes = structure.getAxes().stream().map(axis -> {
                            return axis.name() + ": " + Long.toHexString(structure.getSeriesOffset(axis)) + "\r\n";
                        }).collect(Collectors.joining());

                        String message = "Table found in " + calibration.getName() + ":\r\n" +
                                "Root: " + Long.toHexString(structure.getRootOffset()) + "\r\n" +
                                "Data: " + Long.toHexString(structure.getDataOffset()) + "\r\n" +
                                axes;

                        JEditorPane jep = new JEditorPane("text/plain", message);
                        jep.setEditable(false);
                        jep.setBorder(null);

                        SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(editor, jep,
                                "Table Found - " + table.getName(),
                                JOptionPane.INFORMATION_MESSAGE));
                    } else {
                        SwingUtilities.invokeLater(() -> {
                            Errors.show(editor, "Search failed", "Could not find table \"" + table.getName() + "\".");
                        });
                    }
                });
    }

    public static void defineTableByAddress(Editor editor) {
        Calibration calibration = editor.getCalibration();
        if (calibration == null) {
            Errors.show(editor, "Search tables failed", "No calibration is selected.");
            return;
        }

        Variant variant = calibration.getVariant();
        OSType osType = variant.getOSType();
        if (osType == null) {
            Errors.show(editor, "Define table failed", "The current variant \""
                    + variant.getName() + "\" does not have an OS specified.");
            return;
        }

        OS os;
        try {
            os = osType.createOS(calibration);
        } catch (IOException e) {
            Errors.show(editor, "OS load failed", "Problem loading OS!", e);
            return;
        }

        MemoryAddress address = MemoryAddressDialog.show(editor, EnumSet.of(MemoryType.CODE), null);

        if (address == null) {
            return;
        }

        Project project = editor.getProject();
        TableExecution execution;
        Table table;
        try {
            // Try to find the table's metadata
            execution = os.inspectCode(address.getOffset(variant));

            if (execution == null) {
                Errors.show(editor, "Define table failed", "No table execution was found at offset " +
                        address.toString(variant) + ".");
                return;
            }

            TablePlan layout = execution.getFunction().inspect();
            TableStructure structure = layout.getStructure(execution);

            // Define a new table
            table = structure.createTable(calibration);

            // Try to see if it's already defined
            long dataOffset = table.getData().getAddress().getOffset(variant);
            Table existing = project.getTables().stream()
                    .filter(t -> t.isVariantSupported(variant))
                    .filter(t -> t.getData().getAddress().getOffset(variant) == dataOffset)
                    .findFirst().orElse(null);

            // Match table axes to make life easier for people
            List<Table> existingTables = editor.getProject().getTables().stream().filter(
                    t -> t.isVariantSupported(variant)).toList();
            matchTableAxes(existingTables, table, variant);

            if (existing != null) {
                table = existing;
            } else {
                table.setup(project);
            }
        } catch (Exception e) {
            Errors.show(editor, "Find table failed", "Problem reading table!", e);
            return;
        }

        editor.openTableDefinition(table);
    }

    public static void findTables(Editor editor) {
        OS os = loadOs(editor);
        if (os == null) {
            return;
        }

        editor.executeWithProgress("Finding Tables",
                "Searching for tables in \"" + editor.getCalibration() + "\" calibration...",
                (dialog) -> {
            List<TableStructure> structures;

            try {
                structures = os.findTableStructures(dialog);
            } catch (Throwable ex) {
                if (ExceptionUtils.getRootCause(ex) instanceof InterruptedException) {
                    return;
                }

                Errors.show(dialog, "Table search failed", "Problem searching for tables!", ex);
                return;
            }

            List<Table> tables = new ArrayList<>();
            List<Table> existingTables = editor.getProject().getTables().stream().filter(
                    table -> table.isVariantSupported(os.getVariant())).toList();

            try {
                for (int i = 0; i < structures.size(); i++) {
                    dialog.updateProgress("Processing tables...", (float) i / (float) structures.size());

                    TableStructure structure = structures.get(i);
                    long data = structure.getDataOffset();
                    if (tables.stream().anyMatch(table ->
                            table.getData().getAddress().getOffset(os.getVariant()) == data)) {
                        // We already had this table
                        continue;
                    }

                    Table table;
                    try {
                        table = structure.createTable(os.getCalibration());
                    } catch (Exception ex) {
                        continue;
                    }

                    // Match table axes
                    matchTableAxes(existingTables, table, os.getVariant());

                    table.setup(editor.getProject());
                    tables.add(table);
                }
            } finally {
                dialog.dispose();
            }

            if (tables.isEmpty()) {
                Errors.show(editor, "Table search failed", "No tables were found.");
                return;
            }

            TableExplorer explorer = new TableExplorer(editor, os.getCalibration(), tables, table -> {
                table.setup(editor.getProject());
                editor.getProject().getTables().add(table);
                editor.fireModelChange(Model.TABLE, ChangeType.ADDED);
            });

            editor.openWindow(explorer);
        });
    }

    public static void matchTables(Editor editor) {
        OS os = loadOs(editor);
        if (os == null) {
            return;
        }

        List<Calibration> options = editor.getProject().getCalibrations().stream()
                .filter(c -> c.getVariant() != os.getVariant()).toList();

        Calibration sourceCalibration = showOptionDialog(editor,
                "Select Source Calibration", "Select a calibration to match tables from:", options);

        if (sourceCalibration == null) {
            return;
        }

        // Find data references in the source calibration that match the source tables
        OS sourceOs;
        try {
            sourceOs = sourceCalibration.getOS();
        } catch (IOException e) {
            Errors.show(editor, "Table search failed", "Problem loading OS from "
                    + sourceCalibration.getName() + "!", e);
            return;
        }

        editor.executeWithProgress(
                "Matching Tables",
                "Finding tables in " + os.getCalibration() + " that match " + sourceCalibration + "...",
                progressDialog -> {
                    List<TableExecution> sourceExecutions = sourceOs.getExecutions(progressDialog);
                    List<TableStructure> sourceStructures;

                    try {
                        sourceStructures = sourceOs.findTableStructures(sourceExecutions, progressDialog);
                    } catch (Throwable ex) {
                        if (ExceptionUtils.getRootCause(ex) instanceof InterruptedException) {
                            return;
                        }

                        Errors.show(editor, "Table search failed", "Problem searching for tables in "
                                + sourceCalibration.getName() + "!", ex);
                        return;
                    }

                    // Build a list of tables that we would like to have in the current ROM/calibration
                    List<Table> candidates = editor.getProject().getTables().stream()
                            .filter(table -> !table.isVariantSupported(os.getCalibration()))        // we don't support it,
                            .filter(table -> table.isVariantSupported(sourceCalibration)).toList(); // but they do

                    // Map the source table structures we found to tables in the project. This builds a model of the tables
                    // that not only the source calibration supports, but also maps those to a structure in the ROM that
                    // we can use with the OS to find any code pointers to those structs.
                    Map<TableStructure, Table> sourceTableMappings = new HashMap<>();
                    for (TableStructure sourceStructure : sourceStructures) {
                        long data = sourceStructure.getDataOffset();
                        candidates.stream()
                                .filter(table -> table.getData().getOffset(sourceCalibration) == data)
                                .findFirst()
                                .ifPresent(table -> sourceTableMappings.put(sourceStructure, table));
                    }

                    // Find all the tables in the target ROM/calibration
                    List<TableExecution> targetExecutions = os.getExecutions(progressDialog);
                    List<TableStructure> targetStructures;
                    try {
                        targetStructures = os.findTableStructures(targetExecutions, progressDialog);
                    } catch (Throwable ex) {
                        if (ExceptionUtils.getRootCause(ex) instanceof InterruptedException) {
                            return;
                        }

                        Errors.show(editor, "Table search failed", "Problem searching for tables in "
                                + os.getCalibration() + "!", ex);

                        return;
                    }

                    // Now, score every data reference on the source calibration against the tables in the target
                    int scored = 0;
                    TableComparer comparer = os.createComparer();
                    Map<Table, Table> matched = new LinkedHashMap<>();
                    Set<TableStructure> matchedTargets = new HashSet<>();
                    for (TableStructure sourceStructure : sourceStructures) {
                        Table table = sourceTableMappings.get(sourceStructure);
                        if (table == null) {
                            continue;
                        }

                        Table romTable_source = sourceStructure.createTable(sourceCalibration);

                        progressDialog.updateProgress("Matching tables...", (float) scored / (float) sourceStructures.size());

                        TableExecution sourceExecution = sourceStructure.getExecution();
                        Map<TableStructure, Float> scores_code = new LinkedHashMap<>();
                        Map<TableStructure, Float> scores_data = new LinkedHashMap<>();
                        for (TableStructure targetStructure : targetStructures) {
                            if (targetStructure.getAxes().size() != sourceStructure.getAxes().size()) {
                                continue;
                            }

                            if (matchedTargets.contains(targetStructure)) {
                                continue;
                            }

                            TableExecution targetExecution = targetStructure.getExecution();

                            // Score the two tables (type 1, code match)
                            float score_code;
                            try {
                                score_code = comparer.compareCode(sourceExecution, targetExecution);
                            } catch (Exception ex) {
                                score_code = 0;
                            }

                            if (score_code >= 0.75f) {
                                scores_code.put(targetStructure, score_code);
                                continue;
                            }

                            // Score the two tables (type 2, data match)
                            Calibration targetCalibration = targetStructure.getOS().getCalibration();
                            Table romTable_target = targetStructure.createTable(targetCalibration);

                            if (sourceStructure.getAxes().stream().allMatch(axis ->
                                    sourceStructure.getSeriesLength(axis) == targetStructure.getSeriesLength(axis))) {
                                float score_data = romTable_target.compareTo(targetCalibration,
                                        romTable_source, sourceCalibration);
                                scores_data.put(targetStructure, score_data);
                            }
                        }

                        scored ++;

                        TableStructure matchedStructure;

                        if (!scores_code.isEmpty()) {
                            matchedStructure = scores_code.entrySet().stream().max(Map.Entry.comparingByValue())
                                    .map(Map.Entry::getKey)
                                    .stream().findFirst().orElse(null);
                        } else {
                            matchedStructure = scores_data.entrySet().stream().min(Map.Entry.comparingByValue())
                                    .map(Map.Entry::getKey)
                                    .stream().findFirst().orElse(null);
                        }

                        if (matchedStructure == null) {
                            continue;
                        }

                        Set<Axis> tableAxes = table.getSupportedAxes();
                        Set<Axis> matchedAxes = matchedStructure.getAxes();
                        if (!matchedAxes.containsAll(tableAxes) || !tableAxes.containsAll(matchedAxes)) {
                            continue;
                        }

                        matchedTargets.add(matchedStructure);

                        Table workingCopy = table.copy();
                        long dataOffset = matchedStructure.getDataOffset();
                        workingCopy.getData().getAddress().setOffset(os.getVariant(), dataOffset);

                        for (Axis axis : workingCopy.getAxes().keySet()) {
                            long axisOffset = matchedStructure.getSeriesOffset(axis);
                            workingCopy.getSeries(axis).getAddress().setOffset(os.getCalibration(), axisOffset);
                        }

                        matched.put(workingCopy, table);
                    }

                    progressDialog.dispose();

                    if (matched.isEmpty()) {
                        SwingUtilities.invokeLater(() ->
                                Errors.show(editor, "Table match failed", "No matching tables were found."));
                        return;
                    }

                    TableExplorer explorer = new TableExplorer(editor, os.getCalibration(), matched.keySet(), workingCopy -> {
                        Table real = matched.get(workingCopy);
                        real.apply(workingCopy);
                        editor.fireModelChange(Model.TABLE, ChangeType.MODIFIED);
                    });

                    editor.openWindow(explorer);
                });
    }

    public static void testOperation(Editor parent, Scale scale) {
        Number data = BinaryInputDialog.show(parent, scale.getFormat());
        if (data == null) {
            return;
        }

        String hexString;

        if (data instanceof Float) {
            hexString = Integer.toHexString((int) (Float.floatToIntBits(data.floatValue()) & 0xFFFFFFFFL));
        } else {
            hexString = Integer.toHexString((int) (data.longValue() & 0xFFFFFFFFL));
        }

        hexString = hexString.toUpperCase();

        float output = scale.forward(data.floatValue());

        java.util.List<String> stages = new LinkedList<>();

        float value = data.floatValue();
        for (ScalingOperation operation : scale.getOperations()) {
            float before = value;
            value = operation.getOperation().forward(value, operation.getCoefficient());
            stages.add(String.format("    %s = <b>%.2f</b>",
                    operation.getOperation().formatString(before, operation.getCoefficient()),
                    value));
        }

        Unit preferredUnit = scale.getUnit().getPreferredUnit();

        String message = "<html>" +
                "<h3>" + scale.getName() + "</h3>" +
                "Input: <code>0x" + hexString + "</code> (dec. <code><b>" + data + "</b></code>)<br/><br/>"
                + "<hr style=\"border-color:gray\"/>"
                + "<h3>Operations:</h3>" +
                "<table>" +
                stages.stream().map(s -> "<tr>" +
                        Arrays.stream(s.trim().split(" ")).map(s2 ->
                                "<td style=\"text-align:right\"><code>" + s2 + "</code></td>").collect(Collectors.joining())
                        + "</tr>"
                ).collect(Collectors.joining("")) +
                "</ul></table><br/>" +
                "<h3>Output:</h3>" +
                "Native: <code><b>" +
                scale.format(output) + scale.getUnit().getText()
                + "</code></b>" +
                (preferredUnit != scale.getUnit() ?
                        "<br/>" +
                                "Preferred: <code><b>" +
                                scale.formatPreferred(output) + preferredUnit.getText()
                                + "</code></b>" : "") +
                "</html>";

        JEditorPane jep = new JEditorPane("text/html", message);
        jep.setEditable(false);
        jep.setBorder(null);

        JOptionPane.showMessageDialog(parent,
                jep,
                "Test Operations - " + scale.getName(),
                JOptionPane.INFORMATION_MESSAGE,
                Icons.get(FontAwesomeSolid.VIAL, 64));
    }

    /**
     * Saves you time by matching the undefined axes of a table you provide with a set of existing tables in your project.
     *
     * @param existingTables a list of existing tables to search for axis/series definition data in.
     * @param table the table to set up
     * @param variant the currently selected Calibration's variant
     */
    private static void matchTableAxes(List<Table> existingTables, Table table, Variant variant) {
        // Try to identify the axes scale
        for (Series series : table.getAllAxes()) {
            long offset = series.getAddress().getOffset(variant);
            existingTables.stream()
                    .flatMap(existing -> existing.getAxes().values().stream())
                    .filter(existingSeries -> existingSeries.getAddress().getOffset(variant) == offset)
                    .findFirst()
                    .ifPresent(match -> {
                        series.setScale(match.getScale());
                        series.setName(match.getName());
                        series.setParameter(match.getParameter());
                    });
        }
    }

    public static void applyCalibration(Editor editor, Predicate<TreeTab.Item> predicate) {
        Project project = editor.getProject();
        Calibration target = editor.getCalibration();

        Object[] options = project.getCalibrations().stream()
                .filter(c -> c != editor.getCalibration())
                .sorted(Comparator.comparing(Calibration::getName)).toArray();

        Calibration source = (Calibration) JOptionPane.showInputDialog(
                editor,
                "Select a calibration to apply to " + target.getName(),
                "Select Calibration",
                JOptionPane.PLAIN_MESSAGE,
                null,
                options,
                null
        );

        if (source == null) {
            return;
        }

        if (source == target) {
            return;
        }

        List<ComparedItem> compared = new ArrayList<>();
        editor.executeWithProgress(
                "Calculating Tables",
                "Comparing \"" + source.getName() + "\" to \"" + target.getName() + "\"...",
                (progressDialog) -> {
                    List<Table> tables = project.getTables().stream().filter(predicate).toList();

                    for (int i = 0; i < tables.size(); i ++) {
                        Table table = tables.get(i);
                        progressDialog.updateProgress("Comparing \"" + table.getName() + "\"...",
                                (float)i / (float)tables.size());

                        boolean source_supported = table.isVariantSupported(source.getVariant());
                        boolean target_supported = table.isVariantSupported(target.getVariant());

                        ComparedTable comparedTable;

                        if (!source_supported && !target_supported) {
                            continue;
                        } else if (!source_supported || !target_supported) {
                            List<Comparison> comparisons = new ArrayList<>();
                            if (!source_supported) {
                                comparisons.add(new DefaultComparison(CompareSeverity.ERROR, CarbonIcons.CLOSE,
                                        source.getName() + " lacks support"));
                            }

                            if (!target_supported) {
                                comparisons.add(new DefaultComparison(CompareSeverity.ERROR, CarbonIcons.CLOSE,
                                        target.getName() + " lacks support"));
                            }

                            comparedTable = new ComparedTable(table, source, target, comparisons);
                        } else {
                            comparedTable = ComparedTable.compare(table, source, target);
                        }

                        compared.add(comparedTable);
                    }

                    if (compared.isEmpty()) {
                        Errors.show(editor, "No Items Found", "Cannot apply "
                                + target.getName() + ": no items found to apply");
                        return;
                    }

                    compared.sort(Comparator.comparing(c -> c.getItem().getTreeName()));

                    ApplyCalibrationWindow window = new ApplyCalibrationWindow(editor, source, target, compared);
                    editor.openWindow(window);
                }
        );
    }
}
