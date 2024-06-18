package com.github.manevolent.atlas.model;

import aQute.lib.io.IO;
import com.github.manevolent.atlas.checked.CheckedConsumer;
import com.github.manevolent.atlas.model.layout.TableLayout;
import com.github.manevolent.atlas.model.layout.TableLayoutType;
import com.github.manevolent.atlas.ui.component.tab.TreeTab;
import org.kordamp.ikonli.Ikon;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import java.io.*;
import java.util.*;
import java.util.function.Consumer;

import static com.github.manevolent.atlas.model.Axis.X;
import static com.github.manevolent.atlas.model.Axis.Y;

public class Table extends AbstractAnchored
        implements TreeTab.Item, Editable<Table> {
    public static final java.awt.Color codeColor = new java.awt.Color(230, 86, 86);
    public static final java.awt.Color eepromColor = new java.awt.Color(230, 230, 86);

    private String name;
    private Series data;
    private Map<Axis, Series> axes;
    private TableLayoutType layoutType = TableLayoutType.STANDARD;
    private TableLayout layout;

    public Table(String name) {
        this.name = name;
    }

    public Table() {

    }

    public Map<Axis, Series> getAxes() {
        return axes;
    }

    public TableLayout getLayout() {
        if (layout == null) {
            layout = layoutType.getFactory().create();
        }

        return layout;
    }

    /**
     * Gets a cell in the table using floating-point axis coordinates. This function can be used when converting one
     * table to another with varying dimensions. In essence, this function emulates typical ECU table logic.
     *
     * @param source memory source (i.e. Calibration) to read table data from.
     * @param coordinates floating-point coordinates
     * @return linearly interpolated cell.
     * @throws IOException
     */
    public float getCalculatedCell(MemorySource source, Map<Axis, Float> coordinates) throws IOException {
        switch (coordinates.size()) {
            case 2:
                return getCalculatedCell(source, coordinates.get(X), coordinates.get(Y));
            case 1:
                return getCalculatedCell(source, getSeries(X), coordinates.get(X));
            case 0:
                return getCell(source);
            default:
                throw new UnsupportedEncodingException(Integer.toString(coordinates.size()));
        }
    }

    private float getCalculatedCell(MemorySource source, float x, float y) throws IOException {
        // Find the limits and gradients on the X axis that the 'x' value corresponds to.
        Series x_series = getSeries(X);
        int x_index = 0;
        float x_value = x_series.get(source, x_index);
        for (; x_index < x_series.getLength() && (x_value = x_series.get(source, x_index)) <= x; x_index ++) { }
        int x_low = Math.min(Math.max(x_index - 1, 0), x_series.getLength() - 1);
        int x_high = Math.min(x_index, x_series.getLength() - 1);
        float x_min = x_series.get(source, x_low), x_max = x_value;
        float x_delta = x_min != x_max ? Math.max(0, Math.min(1, (x - x_min) / (x_max - x_min))) : 0f;

        if (Float.isNaN(x_delta)) {
            x_delta = 0;
        }

        // Find the limits and gradients on the Y axis that the 'y' value corresponds to.
        Series y_series = getSeries(Y);
        int y_index = 0;
        float y_value = y_series.get(source, y_index);
        for (; y_index < y_series.getLength() && (y_value = y_series.get(source, y_index)) <= y; y_index ++) { }
        int y_low = Math.min(Math.max(y_index - 1, 0), y_series.getLength() - 1);
        int y_high = Math.min(y_index, y_series.getLength() - 1);
        float y_min = y_series.get(source, y_low), y_max = y_value;
        float y_delta = y_min != y_max ? Math.max(0, Math.min(1, (y - y_min) / (y_max - y_min))) : 0f;

        if (Float.isNaN(y_delta)) {
            y_delta = 0;
        }

        // Obtain four corners of the desired interpolation
        float a = getCell(source, x_low, y_low);
        float b = getCell(source, x_high, y_low);
        float c = getCell(source, x_low, y_high);
        float d = getCell(source, x_high, y_high);

        // Bi-linear interpolate the corners to a 'k' value, the desired average value between the cells.
        float i = a + ((b - a) * x_delta);
        float j = c + ((d - c) * x_delta);
        float k = i + ((j - i) * y_delta);
        return k;
    }

    private float getCalculatedCell(MemorySource source, Series series, float v) throws IOException {
        int index = 0;
        float x_value = series.get(source, index);
        for (; index < series.getLength() && (x_value = series.get(source, index)) <= v; index ++) { }
        int low = Math.min(Math.max(index - 1, 0), series.getLength() - 1);
        int high = Math.min(index, series.getLength() - 1);
        float min = series.get(source, low), x_max = x_value;
        float delta = Math.max(0, Math.min(1, (v - min) / (x_max - min)));

        if (Float.isNaN(delta)) {
            delta = 0;
        }

        float a = getCell(source, low);
        float b = getCell(source, high);

        float k = a + ((b - a) * delta);;
        return k;
    }

    public float getCell(MemorySource source, Map<Axis, Integer> coordinates) throws IOException {
        return getLayout().get(source, this, coordinates);
    }

    public float getCell(MemorySource source, Integer... coordinates) throws IOException {
        Map<Axis, Integer> coordinatesMap = new HashMap<>();

        for (int n = 0; n < coordinates.length; n ++) {
            int finalN = n;
            Axis axis = Arrays.stream(Axis.values())
                    .filter(a -> a.getIndex() == finalN)
                    .findFirst().orElseThrow();

            coordinatesMap.put(axis, coordinates[n]);
        }

        return getCell(source, coordinatesMap);
    }

    public float setCell(MemorySource source, float value, Map<Axis, Integer> coordinates) throws IOException {
        return getLayout().set(source, this, value, coordinates);
    }

    public float setCell(MemorySource source, float value, Integer... coordinates) throws IOException {
        Map<Axis, Integer> coordinatesMap = new HashMap<>();

        for (int n = 0; n < coordinates.length; n ++) {
            int finalN = n;
            Axis axis = Arrays.stream(Axis.values())
                    .filter(a -> a.getIndex() == finalN)
                    .findFirst().orElseThrow();

            coordinatesMap.put(axis, coordinates[n]);
        }

        return setCell(source, value, coordinatesMap);
    }

    public String getName() {
        return name;
    }

    @Override
    public int getTreeOrdinal() {
        return 1;
    }

    @Override
    public String getTreeName() {
        return getName();
    }

    @Override
    public Ikon getTreeIcon() {
        if (hasAxis(Axis.X) || hasAxis(Axis.Y)) {
            return CarbonIcons.DATA_TABLE;
        } else {
            return CarbonIcons.STRING_INTEGER;
        }
    }

    @Override
    public java.awt.Color getTreeIconColor() {
        Series data = getData();
        if (data == null) {
            return codeColor;
        }

        MemoryAddress address = data.getAddress();
        if (address == null) {
            return codeColor;
        }

        MemorySection section = address.getSection();
        if (section == null) {
            return codeColor;
        }

        MemoryType type = section.getMemoryType();
        if (type == null) {
            return codeColor;
        }

        return type == MemoryType.CODE ? codeColor : eepromColor;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setData(Series data) {
        this.data = data;
    }

    public Series getData() {
        return this.data;
    }

    public Set<Axis> getSupportedAxes() {
        return axes.keySet();
    }

    public void setAxes(Map<Axis, Series> axes) {
        this.axes = axes;
    }

    public void setAxis(Axis axis, Series series) {
        this.axes.put(axis, series);
    }

    public void setLayoutType(TableLayoutType layoutType) {
        if (this.layoutType != layoutType) {
            this.layoutType = layoutType;
            this.layout = null;
        }
    }

    public TableLayoutType getLayoutType() {
        return layoutType;
    }

    public Series getSeries(Axis axis) {
        return this.axes.get(axis);
    }

    public void writeCsv(MemorySource source, OutputStream outputStream, int rounding_precision) throws IOException {
        try (OutputStreamWriter osw = new OutputStreamWriter(outputStream);
                BufferedWriter writer = new BufferedWriter(osw)) {
            Consumer<String> writeCell = (value) -> {
                try {
                    writer.write("\"" + value + "\",");
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            };

            Series y = axes.get(Y);
            Series x = axes.get(X);

            writeCell.accept("");

            if (!axes.isEmpty()) {
                for (int x_index = 0; x_index < x.getLength(); x_index++) {
                    writeCell.accept(String.format("%." + rounding_precision + "f", x.get(source, x_index)));
                }
            }
            writer.write("\r\n");

            if (axes.size() == 2) {
                for (int y_index = 0; y_index < y.getLength(); y_index ++) {
                    // Write the row header
                    writeCell.accept(String.format("%." + rounding_precision + "f", y.get(source, y_index)));
                    for (int x_index = 0; x_index < x.getLength(); x_index ++) {
                        // Write the cell data
                        writeCell.accept(String.format("%." + rounding_precision + "f", getCell(source, x_index, y_index)));
                    }
                    writer.write("\r\n");
                }
            } else if (axes.size() == 1) {
                // Write the row header
                writeCell.accept("");
                for (int x_index = 0; x_index < x.getLength(); x_index ++) {
                    // Write the cell data
                    writeCell.accept(String.format("%." + rounding_precision + "f", getCell(source, x_index)));
                }
                writer.write("\r\n");
            } else if (axes.isEmpty()) {
                // Write the row header
                writeCell.accept("");
                x = data;
                for (int x_index = 0; x_index < x.getLength(); x_index ++) {
                    // Write the cell data
                    writeCell.accept(String.format("%." + rounding_precision + "f", getCell(source, x_index)));
                }
                writer.write("\r\n");
            }

            writeCell.accept("");
            writer.write("\r\n");
            writeCell.accept("Series"); writeCell.accept("Name"); writeCell.accept("Unit");
            writer.write("\r\n");
            writeCell.accept("Table"); writeCell.accept(name);
            if (data.getUnit() != null) {
                writeCell.accept(data.getUnit().name());
            } else {
                writeCell.accept("Unknown!");
            }
            writer.write("\r\n");

            List<Axis> axes = new ArrayList<>(this.axes.keySet());
            axes.sort(Comparator.comparing(Axis::name));
            for (Axis axis : axes) {
                writeCell.accept(axis.name() + " Axis");
                Series series = this.axes.get(axis);
                writeCell.accept(series.getName());
                if (series.getUnit() == null) {
                    writeCell.accept("Unknown!");
                } else {
                    writeCell.accept(this.axes.get(axis).getUnit().name());
                }
                writer.write("\r\n");
            }
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    public boolean hasAxis(Axis axis) {
        return axes.containsKey(axis);
    }

    public Series removeAxis(Axis axis) {
        return axes.remove(axis);
    }

    @Override
    public Table copy() {
        Table copy = new Table();

        copy.axes = Editable.copy(axes);
        copy.name = getName();
        copy.layoutType = getLayoutType();
        copy.data = getData().copy();
        copy.layout = getLayout();

        return copy;
    }

    @Override
    public void apply(Table changed) {
        Editable.apply(axes, changed.axes);
        this.setLayoutType(changed.layoutType);
        this.data.apply(changed.getData());
        this.setName(changed.name);
    }

    public void setup(Project project) {
        if (project == null) {
            throw new NullPointerException("project");
        }

        if (this.layoutType != null) {
            this.layout = this.layoutType.getFactory().create();
        }

        for (Series series : getAllSeries()) {
            Scale scale = series.getScale();
            if (scale.getUnit() == Unit.NONE && Scale.NONE_SCALES.containsValue(scale)) {
                series.setScale(project.getNoneScale(scale.getFormat()));
            }
        }
    }

    private Collection<Series> getAllSeries() {
        ArrayList<Series> series = new ArrayList<>();
        series.addAll(getAllAxes());
        series.add(getData());
        return series;
    }

    public boolean hasData() {
        return data != null && data.getLength() > 0;
    }

    public boolean hasScale(Scale scale) {
        if (getData().getScale() == scale) {
            return true;
        }

        for (Axis axis : axes.keySet()) {
            if (getSeries(axis).getScale() == scale) {
                return true;
            }
        }

        return false;
    }

    @Override
    public String toString() {
        return getName();
    }

    @Override
    public boolean isVariantSupported(Variant variant) {
        if (variant == null) {
            return false;
        }

        return getData().getAddress().hasOffset(variant) &&
                getAllAxes().stream().allMatch(series -> series.getAddress().hasOffset(variant));
    }

    public int forEach(CheckedConsumer<Map<Axis, Integer>, IOException> operation) throws IOException {
        Series x_series = getSeries(X);
        Series y_series = getSeries(Y);

        int x_length = x_series != null ? x_series.getLength() : 1;
        int y_length = y_series != null ? y_series.getLength() : 1;

        Map<Axis, Integer> coordinates = new LinkedHashMap<>();

        int n = 0;
        for (; n < x_length * y_length; n ++) {
            if (x_series != null) {
                int x = n % x_series.getLength();
                coordinates.put(X, x);

                if (y_series != null) {
                    int y = (int) Math.floor(n / (float) x_series.getLength());
                    coordinates.put(Y, y);
                }
            }

            operation.acceptChecked(coordinates);
        }

        return n;
    }

    public List<Variant> getSupportedVariants() {
        return getData().getAddress().getOffsets().keySet().stream().filter(this::isVariantSupported).toList();
    }

    public void updateLength() {
        int n = 1;
        for (Axis axis : axes.keySet()) {
            n *= getSeries(axis).getLength();
        }
        data.setLength(n);
    }

    public Collection<Series> getAllAxes() {
        return axes.values();
    }

    public int getDimensions() {
        return axes.size();
    }

    public float compareTo(Calibration thisCalibration, Table other, Calibration otherCalibration) throws IOException {
        int dimensions = getDimensions();
        if (dimensions == 1) {
            return compareTo_1D(thisCalibration, other, otherCalibration);
        } else if (dimensions == 2) {
            return compareTo_2D(thisCalibration, other, otherCalibration);
        } else {
            throw new UnsupportedOperationException(Integer.toString(dimensions));
        }
    }

    private float compareTo_1D(Calibration thisCalibration, Table other, Calibration otherCalibration)
            throws IOException {
        Series x_series = getSeries(X);
        Map<Axis, Float> coordinates = new HashMap<>();
        float sum = 0f;

        DataFormat thisFormat = getData().getFormat();
        DataFormat otherFormat = other.getData().getFormat();

        int length = x_series.getLength();

        for (int x = 0; x < length; x ++) {
            float x_anchor = x_series.get(thisCalibration, x);
            coordinates.put(X, x_anchor);

            float value_this = thisFormat.convertToScalar(getCell(thisCalibration, x));
            float value_other = otherFormat.convertToScalar(other.getCalculatedCell(otherCalibration, coordinates));
            float difference = value_this - value_other;
            sum += (float) Math.pow(difference, 2);
        }

        return (float) Math.sqrt(sum / length);
    }

    private float compareTo_2D(Calibration thisCalibration, Table other, Calibration otherCalibration)
            throws IOException {
        Series x_series = getSeries(X);
        Series y_series = getSeries(Y);

        Map<Axis, Float> coordinates = new HashMap<>();
        float sum = 0f;

        DataFormat thisFormat = getData().getFormat();
        DataFormat otherFormat = other.getData().getFormat();

        int x_length = x_series.getLength();
        int y_length = y_series.getLength();

        for (int x = 0; x < x_length; x ++) {
            float x_anchor = x_series.get(thisCalibration, x);
            coordinates.put(X, x_anchor);

            for (int y = 0; y < y_length; y ++) {
                float y_anchor = y_series.get(thisCalibration, y);
                coordinates.put(Y, y_anchor);

                float value_this = thisFormat.convertToScalar(getCell(thisCalibration, x, y));
                float value_other = otherFormat.convertToScalar(other.getCalculatedCell(otherCalibration, coordinates));
                float difference = value_this - value_other;
                sum += (float) Math.pow(difference, 2);
            }
        }

        return (float) Math.sqrt(sum / (x_length * y_length));
    }

    public Map<Axis, Float> convertCoordinatesToAnchors(MemorySource memorySource, Map<Axis, Integer> coordinates)
            throws IOException {
        Map<Axis, Float> anchors = new HashMap<>();
        for (Axis axis : coordinates.keySet()) {
            Series series = getSeries(axis);
            anchors.put(axis, series.get(memorySource, coordinates.get(axis)));
        }
        return anchors;
    }

    public static class Builder {
        private final Table table = new Table();

        public Builder() {
            table.setAxes(new LinkedHashMap<>());
        }

        public Builder withName(String name) {
            table.setName(name);
            return this;
        }

        public Builder withData(Series series) {
            table.setData(series);
            return this;
        }

        public Builder withData(Series.Builder series) {
            return withData(series.build());
        }

        public Builder withAxis(Axis axis, Series series) {
            table.setAxis(axis, series);
            return this;
        }

        public Builder withAxis(Axis axis, Series.Builder series) {
            return withAxis(axis, series.build());
        }

        public Builder withLayoutType(TableLayoutType layoutType) {
            table.setLayoutType(layoutType);
            return this;
        }

        public Table build() {
            table.updateLength();
            return table;
        }
    }
}
