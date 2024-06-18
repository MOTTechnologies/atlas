package com.github.manevolent.atlas.logic;

import com.github.manevolent.atlas.model.*;
import com.github.manevolent.atlas.ui.behavior.ProgressListener;
import com.github.manevolent.atlas.ui.util.Jobs;

import java.io.IOException;
import java.nio.ByteOrder;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

/**
 * Describes an ECU OS
 */
public interface OS {

    /**
     * Gets the name of this OS
     * @return OS name
     */
    OSType getType();

    /**
     * Gets the calibration that corresponds to this OS instance.
     * @return calibration.
     */
    Calibration getCalibration();

    /**
     * Gets the byte order for this OS architecture.
     * @return byte order.
     */
    ByteOrder getByteOrder();

    /**
     * Gets a list of properties this OS offers for calibrations.
     * @return properties.
     */
    List<PropertyDefinition> getPropertyDefinitions();

    /**
     * Gets the supported DTC for this calibration.
     * @return supported DTC
     */
    List<SupportedDTC> getSupportedDTC() throws IOException;

    /**
     * Gets the variant that corresponds to this OS calibration.
     * @return calibration variant.
     */
    default Variant getVariant() {
        return getCalibration().getVariant();
    }

    /**
     * Finds table structures in a calibration/ROM.
     *
     * @param listener          a progress listener to relay progress information to a UI.
     * @return a list of table structures.
     */
    default List<TableStructure> findTableStructures(ProgressListener listener)
            throws IOException {
        List<TableExecution> executions = getExecutions(listener);
        return findTableStructures(executions, listener);
    }

    /**
     * Finds table structures in a calibration/ROM.
     *
     * @param listener          a progress listener to relay progress information to a UI.
     * @param executions        a list of table executions to find table structures for.
     * @return a list of table structures.
     */
    default List<TableStructure> findTableStructures(List<TableExecution> executions, ProgressListener listener)
            throws IOException {
        AtomicInteger completed = new AtomicInteger();

        try {
            return Jobs.parallelize(executions.stream().parallel()
                    .flatMap(ref -> {
                        if (Thread.interrupted()) {
                            throw new RuntimeException(new InterruptedException());
                        }

                        int num = completed.incrementAndGet();
                        listener.updateProgress("Searching for tables in " + getCalibration().getName()
                                + "...", (float)num /(float) executions.size());

                        TableStructure structure;

                        try {
                            TablePlan layout = ref.getFunction().inspect();
                            structure = layout.getStructure(ref);
                        } catch (Exception ex) {
                            structure = null;
                        }

                        if (structure != null) {
                            return Stream.of(structure);
                        } else {
                            return Stream.empty();
                        }
                    }));
        } catch (ExecutionException | InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Attempts to find a table structure at a given offset. The offset should be the pointer that assembly
     * code references.
     *
     * @param offset offset to look for a table structure at.
     * @return TableStructure instance if a table was found, null otherwise.
     * @throws IOException if there is an I/O problem reading or finding the table structure.
     */
    TableExecution inspectCode(long offset) throws IOException;

    /**
     * Gets data references in a calibration/ROM by searching for instructions that point at data regions.
     * @param progressListener a progress listener to relay progress information to a UI.
     * @return a list of data references.
     */
    List<TableExecution> getExecutions(ProgressListener progressListener) throws IOException;

    TableComparer createComparer();

}
