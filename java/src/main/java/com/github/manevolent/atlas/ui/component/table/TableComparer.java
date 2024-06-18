package com.github.manevolent.atlas.ui.component.table;

import com.github.manevolent.atlas.model.*;
import com.github.manevolent.atlas.model.layout.TableLayout;
import com.github.manevolent.atlas.model.layout.TableLayoutType;
import com.github.manevolent.atlas.ui.Editor;
import com.github.manevolent.atlas.ui.component.Window;
import com.github.manevolent.atlas.ui.util.Icons;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import javax.help.UnsupportedOperationException;
import javax.swing.*;

import java.io.IOException;
import java.util.*;

import static com.github.manevolent.atlas.model.Axis.X;
import static com.github.manevolent.atlas.model.Axis.Y;
import static com.github.manevolent.atlas.ui.util.Fonts.getTextColor;

public class TableComparer extends Window {
    private final ComparedTable comparedTable;
    private CompareOperation operation;
    private TableEditor preview;

    public TableComparer(Editor editor,
                            Table a_table, Calibration a_calibration,
                            Table b_table, Calibration b_calibration,
                            CompareOperation operation) {
        super(editor);

        this.operation = operation;
        this.comparedTable = new ComparedTable(a_table, a_calibration, b_table, b_calibration);
    }

    @Override
    public String getTitle() {
        if (comparedTable.a_table != comparedTable.b_table) {
            return "Compare Tables - " + comparedTable.a_table + " & " + comparedTable.b_table;
        } else {
            return "Compare Table - "
                    + comparedTable.a_table + " - "
                    + comparedTable.a_calibration + " & " + comparedTable.b_calibration;
        }
    }

    @Override
    public Icon getIcon() {
        return Icons.get(CarbonIcons.DATA_TABLE, getTextColor());
    }

    @Override
    public void reload() {

    }

    @Override
    protected void initComponent(JInternalFrame frame) {
        preview = new TableEditor(getEditor(), comparedTable, comparedTable.a_calibration, true);
        frame.add(preview.getComponent().getContentPane());
    }

    private class ComparedTable extends Table {
        // Base table
        protected final Table a_table;
        protected final Calibration a_calibration;

        // Compared table
        protected final Table b_table;
        protected final Calibration b_calibration;

        protected final ComparedData data;

        private ComparedTable(Table aTable, Calibration aCalibration, Table bTable, Calibration bCalibration) {
            a_table = aTable;
            a_calibration = aCalibration;
            b_table = bTable;
            b_calibration = bCalibration;

            this.data = new ComparedData(this);
        }

        @Override
        public Series getData() {
            return data;
        }

        @Override
        public Collection<Series> getAllAxes() {
            return a_table.getAllAxes();
        }

        @Override
        public Map<Axis, Series> getAxes() {
            return a_table.getAxes();
        }

        @Override
        public int getDimensions() {
            return a_table.getDimensions();
        }

        @Override
        public TableLayout getLayout() {
            return a_table.getLayout();
        }

        @Override
        public boolean hasData() {
            return a_table.hasData() && b_table.hasData();
        }

        @Override
        public boolean hasAxis(Axis axis) {
            return a_table.hasAxis(axis) && b_table.hasAxis(axis);
        }

        @Override
        public boolean hasScale(Scale scale) {
            return a_table.hasScale(scale);
        }

        @Override
        public TableLayoutType getLayoutType() {
            return a_table.getLayoutType();
        }

        @Override
        public Set<Axis> getSupportedAxes() {
            return a_table.getSupportedAxes();
        }

        @Override
        public List<Variant> getSupportedVariants() {
            return a_table.getSupportedVariants();
        }

        @Override
        public boolean isVariantSupported(Variant variant) {
            return a_table.isVariantSupported(variant);
        }

        @Override
        public String getName() {
            return a_table.getName();
        }

        @Override
        public Series getSeries(Axis axis) {
            return a_table.getSeries(axis);
        }

        @Override
        public void setName(String name) {
            throw new UnsupportedOperationException();
        }

        @Override
        public float setCell(MemorySource source, float value, Integer... coordinates) throws IOException {
            throw new UnsupportedOperationException();
        }

        @Override
        public void setAxes(Map<Axis, Series> axes) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void setAxis(Axis axis, Series series) {
            throw new UnsupportedOperationException();
        }

        @Override
        public float setCell(MemorySource source, float value, Map<Axis, Integer> coordinates) throws IOException {
            throw new UnsupportedOperationException();
        }

        @Override
        public void setLayoutType(TableLayoutType layoutType) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void setData(Series data) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void setup(Project project) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void updateLength() {
            throw new UnsupportedOperationException();
        }
    }

    private class ComparedData extends Series {
        private final ComparedTable comparedTable;
        private final Series a_data;

        private ComparedData(ComparedTable comparedTable) {
            this.comparedTable = comparedTable;
            this.a_data = comparedTable.a_table.getData();
        }

        @Override
        public void apply(Series other) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Series copy() {
            throw new UnsupportedOperationException();
        }

        @Override
        public DataFormat getFormat() {
            return a_data.getFormat();
        }

        @Override
        public int getLength() {
            return a_data.getLength();
        }

        @Override
        public String getName() {
            return a_data.getName();
        }

        @Override
        public Scale getScale() {
            return a_data.getScale();
        }

        @Override
        public Unit getUnit() {
            return a_data.getUnit();
        }

        @Override
        public float set(MemorySource source, int index, float value) throws IOException {
            throw new UnsupportedOperationException();
        }

        @Override
        public void setAll(MemorySource source, float[] data) throws IOException {
            throw new UnsupportedOperationException();
        }

        @Override
        public void setAddress(MemoryAddress address) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void setLength(int length) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void setName(String name) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void setParameter(MemoryParameter parameter) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void setScale(Scale scale) {
            throw new UnsupportedOperationException();
        }

        @Override
        public MemoryParameter getParameter() {
            return null;
        }

        @Override
        public MemoryAddress getAddress() {
            return a_data.getAddress();
        }

        /**
         * Compare the value at the requested location.
         * @param source the memory source to read from (should always be the comparing 'a' calibration).
         * @param index the index to read (x,y should be inferred by the implementation).
         * @return the delta value of the two compared tables.
         * @throws IOException if there is a problem reading data from the calibration.
         */
        @Override
        public float get(MemorySource source, int index) throws IOException {
            Table a = comparedTable.a_table;
            Table b = comparedTable.b_table;

            float a_data = a.getData().get(source, index);

            Series x_series = a.getSeries(X);
            Series y_series = a.getSeries(Y);

            int x, y;
            if (y_series != null) {
                x = index % x_series.getLength();
                y = (int) Math.floor(index / (float) x_series.getLength());
            } else if (x_series != null) {
                x = index;
                y = 0;
            } else if (index != 0) {
                throw new IllegalArgumentException("index != 0: " + index);
            } else {
                x = 0;
                y = 0;
            }

            Map<Axis, Float> coordinates = new HashMap<>();
            if (x_series != null) {
                coordinates.put(X, x_series.get(source, x));
            }
            if (y_series != null) {
                coordinates.put(Y, y_series.get(source, y));
            }

            float b_data = b.getCalculatedCell(comparedTable.b_calibration, coordinates);

            switch (operation) {
                case SUBTRACT:
                    return b_data - a_data;
                case SUM:
                    return b_data + a_data;
                default:
                    throw new UnsupportedOperationException(operation.name());
            }
        }
    }

    public enum CompareOperation {
        SUM,
        SUBTRACT
    }
}
