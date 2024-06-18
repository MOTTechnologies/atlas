package com.github.manevolent.atlas.logic.subaru;

import com.github.manevolent.atlas.logic.TablePlan;

import javax.help.UnsupportedOperationException;
import java.util.*;
import java.util.stream.Collectors;

public class SubaruDITableInspector2D extends SubaruDITableInspector {
    public SubaruDITableInspector2D(SubaruDITableFunction function) {
        super(function);
    }

    @Override
    public TablePlan inspect() {
        SubaruDITableFunction function = getFunction();

        int result;

        int x_size_offset = -1, y_size_offset = -1;
        int x_data_offset = -1, y_data_offset = -1, data_offset = -1;
        int x_data_size = -1, y_data_size = -1, data_size = -1;

        // Emulate the function, recording the behavior of it in the process in several protected fields in the parent
        // class
        result = (int) function.emulate(this, 0, 4 - 1);

        // First, discern where the axis sizes are stored

        // Extract the sizes of each structure component
        // There are two of these: a and b. Each corresponds to an axis.
        // a=x and b=y, or a=y and b=x.
        int a_size_offset = (int) (lengthToStruct.get(a_length) - root);
        int b_size_offset = (int) (lengthToStruct.get(b_length) - root);

        // Switch over the value the OS firmware function returned
        switch (result) {
            case 3: // X-axis was long enough to supply this value
                // Typical scenario when a=y and b=x
                x_size_offset = a_size_offset;
                y_size_offset = b_size_offset;
                break;
            case 2: // Ran over the X-axis
                // a=x and b=y
                x_size_offset = b_size_offset;
                y_size_offset = a_size_offset;
                break;
            default:
                throw new UnsupportedOperationException("unexpected result: " + result);
        }

        // Next, discern where the axis contents are stored based on the order that the structure pointer arrays
        // were read
        Iterator<Long> scanIterator = scanOrder.iterator();
        long x_axis_root = scanIterator.next();
        long y_axis_root = scanIterator.next();
        long x_axis_struct = dataToStruct.getOrDefault(x_axis_root, -1L);
        long y_axis_struct = dataToStruct.getOrDefault(y_axis_root, -1L);
        x_data_offset = (int) (x_axis_struct - root);
        y_data_offset = (int) (y_axis_struct - root);

        // Next, discern where the data content would be based on which array, of the three, WASN'T scanned.
        long data_root = readOrder.stream().filter(addr -> addr != x_axis_root && addr != y_axis_root).findFirst()
                .orElseThrow(() -> new UnsupportedOperationException("failed to find data root"));
        long data_struct = dataToStruct.getOrDefault(data_root, -1L);
        data_offset = (int) (data_struct - root);

        x_data_size = axisDataSizes.getOrDefault(x_axis_root, -1);
        y_data_size = axisDataSizes.getOrDefault(y_axis_root, -1);
        data_size = axisDataSizes.getOrDefault(data_root, -1);

        // Ensure all offsets/sizes were identified
        Set<String> missingVariables = new LinkedHashSet<>();
        checkVariable("x_size_offset", x_size_offset, missingVariables);
        checkVariable("y_size_offset", y_size_offset, missingVariables);

        if (x_size_offset == y_size_offset) {
            throw new UnsupportedOperationException("size offsets conflict: x size == y size");
        }

        checkVariable("x_data_offset", x_data_offset, missingVariables);
        checkVariable("y_data_offset", y_data_offset, missingVariables);
        checkVariable("data_offset", data_offset, missingVariables);

        if (x_data_offset == y_data_offset || x_data_offset == data_offset || y_data_offset == data_offset) {
            throw new UnsupportedOperationException("array offsets conflict");
        }

        checkVariable("x_data_size", x_data_size, 1, missingVariables);
        checkVariable("y_data_size", y_data_size, 1, missingVariables);
        checkVariable("data_size", data_size, 1, missingVariables);

        if (!missingVariables.isEmpty()) {
            throw new UnsupportedOperationException("missing variables: " + String.join(", ", missingVariables));
        }

        // Create the table plan
        return new SubaruDITablePlan2D(getFunction(),
                x_size_offset, y_size_offset,
                x_data_offset, y_data_offset, data_offset,
                data_size, x_data_size, y_data_size);
    }
}
