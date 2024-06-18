package com.github.manevolent.atlas.math;

import com.github.manevolent.atlas.model.Calibration;
import com.github.manevolent.atlas.model.Table;
import com.github.manevolent.atlas.settings.Settings;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static com.github.manevolent.atlas.model.Axis.X;
import static com.github.manevolent.atlas.model.Axis.Y;

/**
 * Helper class to isolate table interpolate functions.
 */
public final class TableInterpolation {

    /**
     * Interpolate a table, modifying the cells as necessary.
     *
     * @param type type of interpolation to perform (i.e. InterpolationType.LINEAR)
     * @param table table to interpolate the cells of
     * @param rows an array of selected rows
     * @param cols an array of selected columns
     */
    public static void interpolate(InterpolationType type, Table table, Calibration calibration,
                                   int[] rows, int[] cols) throws IOException {
        interpolate(type.getFunction(), table, calibration, rows, cols);
    }

    public static void interpolate(InterpolationFunction func, Table table, Calibration calibration,
                                   int[] rows, int[] cols) throws IOException {
        if ((rows.length == 0 || cols.length == 0) || (rows.length == 1 && cols.length == 1)) {
            // Nothing to do
          return;
        }

        List<Region> regions = new ArrayList<>();
        for (int rowIndex = 1; rowIndex < rows.length; rowIndex++) {
            int y = rows[rowIndex];
            int last_y = rows[rowIndex - 1];
            for (int x : cols) {
                regions.add(new RowRegion(last_y, y, x));
            }
        }

        for (int colIndex = 1; colIndex < cols.length; colIndex++) {
            int x = cols[colIndex];
            int last_x = cols[colIndex - 1];
            for (int y : rows) {
                regions.add(new ColumnRegion(last_x, x, y));
            }
        }

        for (int colIndex = 0; colIndex < cols.length - 1; colIndex++) {
            int low_col = cols[colIndex];
            int high_col = cols[colIndex + 1];
            if (high_col - low_col <= 1) {
                continue;
            }

            for (int rowIndex = 0; rowIndex < rows.length - 1; rowIndex++) {
                int low_row = rows[rowIndex];
                int high_row = rows[rowIndex + 1];
                if (high_row - low_row <= 1) {
                    continue;
                }

                regions.add(new InnerRegion(low_col, low_row, high_col, high_row));
            }
        }

        for (Region region : regions) {
            region.interpolate(table, calibration, func);
        }
    }

    private interface Region {
        void interpolate(Table table, Calibration calibration, InterpolationFunction func) throws IOException;
    }

    private static class RowRegion implements Region {
        private final int row_a, row_b, col;

        private RowRegion(int row_a, int row_b, int col) {
            this.row_a = row_a;
            this.row_b = row_b;
            this.col = col;
        }

        @Override
        public void interpolate(Table table, Calibration calibration, InterpolationFunction func) throws IOException {
            float a = table.getCell(calibration, col, row_a);
            float b = table.getCell(calibration, col, row_b);

            for (int i = row_a + 1; i < row_b; i ++) {
                float v;
                if (Settings.TABLE_EDITOR_AXIS_AWARE_INTERP.get()) {
                    float row_a_val = table.getSeries(Y).get(calibration, row_a);
                    float row_b_val = table.getSeries(Y).get(calibration, row_b);
                    float i_val = table.getSeries(Y).get(calibration, i);
                    v = (i_val - row_a_val) / (row_b_val - row_a_val);
                } else {
                    v = (float) (i - row_a) / (row_b - row_a);
                }
                v = func.interpolate(a, b, v);
                table.setCell(calibration, v, col, i);
            }
        }
    }

    private static class ColumnRegion implements Region {
        private final int col_a, col_b, row;

        private ColumnRegion(int col_a, int col_b, int row) {
            this.col_a = col_a;
            this.col_b = col_b;
            this.row = row;
        }

        @Override
        public void interpolate(Table table, Calibration calibration, InterpolationFunction func) throws IOException {
            float a = table.getCell(calibration, col_a, row);
            float b = table.getCell(calibration, col_b, row);
            for (int i = col_a + 1; i < col_b; i ++) {
                float v;
                if (Settings.TABLE_EDITOR_AXIS_AWARE_INTERP.get()) {
                    float col_a_val = table.getSeries(X).get(calibration, col_a);
                    float col_b_val = table.getSeries(X).get(calibration, col_b);
                    float i_val = table.getSeries(X).get(calibration, i);
                    v = (i_val - col_a_val) / (col_b_val - col_a_val);
                } else {
                    v = (float) (i - col_a) / (col_b - col_a);
                }

                v = func.interpolate(a, b, v);
                table.setCell(calibration, v, i, row);
            }
        }
    }

    private static class InnerRegion implements Region {
        private final int lowCol, lowRow, highCol, highRow;

        public InnerRegion(int lowCol, int lowRow, int highCol, int highRow) {
            this.lowCol = lowCol;
            this.lowRow = lowRow;
            this.highCol = highCol;
            this.highRow = highRow;
        }

        @Override
        public void interpolate(Table table, Calibration calibration, InterpolationFunction func) throws IOException {
            // The 'top' horizontal component
            float a = table.getCell(calibration, lowCol, lowRow);
            float b = table.getCell(calibration, highCol, lowRow);

            // The 'bottom' horizontal component
            float c = table.getCell(calibration, lowCol, highRow);
            float d = table.getCell(calibration, highCol, highRow);

            for (int i = lowCol + 1; i < highCol; i ++) {
                float u;

                if (Settings.TABLE_EDITOR_AXIS_AWARE_INTERP.get()) {
                    float low_col_val = table.getSeries(X).get(calibration, lowCol);
                    float high_col_val = table.getSeries(X).get(calibration, highCol);
                    float i_val = table.getSeries(X).get(calibration, i);
                    u = (i_val - low_col_val) / (high_col_val - low_col_val);
                } else {
                    u = (float) (i - lowCol) / (highCol - lowCol); // The horizontal delta
                }

                for (int j = lowRow + 1; j < highRow; j ++) {
                    float v;
                    if (Settings.TABLE_EDITOR_AXIS_AWARE_INTERP.get()) {
                        float low_row_val = table.getSeries(Y).get(calibration, lowRow);
                        float high_row_val = table.getSeries(Y).get(calibration, highRow);
                        float i_val = table.getSeries(Y).get(calibration, j);
                        v = (i_val - low_row_val) / (high_row_val - low_row_val);
                    } else {
                        v = (float) (j - lowRow) / (highRow - lowRow); // The vertical delta
                    }

                    float x1 = func.interpolate(a, b, u);
                    float x2 = func.interpolate(c, d, u);
                    float y = func.interpolate(x1, x2, v);
                    table.setCell(calibration, y, i, j);
                }
            }
        }
    }
}

