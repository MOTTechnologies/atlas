package com.github.manevolent.atlas.ui.component.toolbar;

import com.github.manevolent.atlas.model.Calibration;
import com.github.manevolent.atlas.ui.Editor;
import com.github.manevolent.atlas.ui.component.table.TableEditor;

import org.kordamp.ikonli.carbonicons.CarbonIcons;
import org.kordamp.ikonli.fontawesome5.FontAwesomeSolid;

import javax.swing.*;
import java.util.List;

public class TableEditorToolbar extends CalibrationToolbar<TableEditor> {
    public TableEditorToolbar(TableEditor editor) {
        super(editor);
    }

    @Override
    public Editor getEditor() {
        return getParent().getEditor();
    }

    @Override
    protected void initLeftComponent(JToolBar toolbar) {
        toolbar.add(makeButton(CarbonIcons.CHART_CUSTOM, "define", "Edit table definition", (e) -> {
            getEditor().openTableDefinition(getParent().getTable());
        }));

        toolbar.addSeparator();

        toolbar.add(makeButton(FontAwesomeSolid.FILE_DOWNLOAD, "apply", "Apply other table...",
                (e) -> getParent().applyTable()));

        toolbar.addSeparator();

        toolbar.add(makeButton(FontAwesomeSolid.TIMES, "multiply", "Multiply value at selected cells",
                (e) -> getParent().scaleSelection()));
        toolbar.add(makeButton(FontAwesomeSolid.DIVIDE, "divide", "Divide value at selected cells",
                (e) -> getParent().divideSelection()));
        toolbar.add(makeButton(FontAwesomeSolid.PLUS, "add", "Add value to selected cells",
                (e) -> getParent().addSelection()));

        toolbar.addSeparator();

        toolbar.add(makeButton(FontAwesomeSolid.PERCENTAGE, "percent", "Scale values with a percentage",
                (e) -> getParent().scaleSelection()));
        toolbar.add(makeButton(FontAwesomeSolid.EQUALS, "average", "Average values in selection",
                (e) -> getParent().averageSelection()));
        toolbar.add(makeButton(CarbonIcons.CONTAINER_SOFTWARE, "interpolate", "Interpolate values using selection",
                (e) -> getParent().interpolateSelection()));


        toolbar.addSeparator();
    }

    @Override
    protected Calibration setCalibration(Calibration calibration) {
        if (getParent().setCalibration(calibration)) {
            return calibration;
        } else {
            return getCalibration();
        }
    }

    @Override
    protected Calibration getCalibration() {
        return getParent().getCalibration();
    }

    @Override
    protected List<Calibration> getCalibrations() {
        return getEditor().getProject().getCalibrations();
    }
}
