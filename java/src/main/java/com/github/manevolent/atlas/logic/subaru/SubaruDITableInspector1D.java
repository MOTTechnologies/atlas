package com.github.manevolent.atlas.logic.subaru;

import com.github.manevolent.atlas.logic.TablePlan;

import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

public class SubaruDITableInspector1D extends SubaruDITableInspector {
    public SubaruDITableInspector1D(SubaruDITableFunction function) {
        super(function);
    }

    @Override
    public TablePlan inspect() {
        SubaruDITableFunction function = getFunction();

        int result;

        int x_size_offset = -1;
        int x_data_offset = -1, data_offset = -1;
        int x_data_size = -1, data_size = -1;

        result = (int) function.emulate(this, 4 - 1);

        // Switch over the value the OS firmware function returned
        switch (result) {
            // Typical scenario when a=x and b=y
            case 27:
                x_size_offset = (int) (lengthToStruct.get(a_length) - root);

                for (Map.Entry<Long, Integer> entry : maxReadValue.entrySet()) {
                    int size = axisDataSizes.get(entry.getKey());

                    if (entry.getValue() == 27) {
                        data_offset = (int) (dataToStruct.get(entry.getKey()) - root);
                        data_size = size;
                    } else {
                        x_data_offset = (int) (dataToStruct.get(entry.getKey()) - root);
                        x_data_size = size;
                    }
                }

                break;
        }

        // Ensure all offsets/sizes are identified
        Set<String> missingVariables = new LinkedHashSet<>();
        checkVariable("x_size_offset", x_size_offset, missingVariables);
        checkVariable("x_data_offset", x_data_offset, missingVariables);
        checkVariable("data_offset", data_offset, missingVariables);
        checkVariable("x_data_size", x_data_size, missingVariables);
        checkVariable("data_size", data_size, missingVariables);
        if (!missingVariables.isEmpty()) {
            throw new UnsupportedOperationException("missing variables: " + String.join(", ", missingVariables));
        }

        return new SubaruDITablePlan1D(function.getOS(), function, x_size_offset, x_data_offset, data_offset,
                data_size, x_data_size);
    }
}
