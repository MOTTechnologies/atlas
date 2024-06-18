package com.github.manevolent.atlas.ui.component.toolbar;

import com.github.manevolent.atlas.ui.Editor;
import com.github.manevolent.atlas.ui.component.datalog.DatalogPage;
import com.github.manevolent.atlas.ui.component.datalog.DatalogWindow;
import com.github.manevolent.atlas.ui.util.Fonts;
import com.github.manevolent.atlas.ui.util.Icons;
import com.github.manevolent.atlas.ui.util.Labels;
import org.kordamp.ikonli.carbonicons.CarbonIcons;
import org.kordamp.ikonli.swing.FontIcon;

import javax.swing.*;
import java.awt.*;

public class DatalogToolbar extends Toolbar<DatalogWindow> {
    private JButton pauseButton;
    private JLabel tLabel;

    public DatalogToolbar(DatalogWindow editor) {
        super(editor);
    }

    @Override
    public Editor getEditor() {
        return getParent().getEditor();
    }

    @Override
    protected void preInitComponent(JToolBar toolbar) {
        super.preInitComponent(toolbar);

        toolbar.setOrientation(JToolBar.HORIZONTAL);
        toolbar.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, Color.GRAY.darker()));
    }

    @Override
    protected void initComponent(JToolBar toolbar) {
        toolbar.add(pauseButton = makeButton(CarbonIcons.RECORDING_FILLED, "record", "Record new datalog", (e) -> {
            getParent().toggleRecording();
        }));

        toolbar.addSeparator();

        toolbar.add(makeButton(CarbonIcons.FIT_TO_SCREEN, "fit", "Fit to width", (e) -> {
            DatalogPage activePage = getParent().getActivePage();
            if (activePage != null) {
                activePage.fitToScreen();
            }
        }));
        toolbar.add(makeButton(CarbonIcons.ARROW_LEFT, "left", "Move left", (e) -> {
            DatalogPage activePage = getParent().getActivePage();
            if (activePage != null) {
                activePage.moveLeft();
            }
        }));
        toolbar.add(makeButton(CarbonIcons.ARROW_RIGHT, "right", "Move right", (e) -> {
            DatalogPage activePage = getParent().getActivePage();
            if (activePage != null) {
                activePage.moveRight();
            }
        }));
        toolbar.add(makeButton(CarbonIcons.ZOOM_IN, "zoomIn", "Zoom in", (e) -> {
            DatalogPage activePage = getParent().getActivePage();
            if (activePage != null) {
                activePage.zoomIn();
            }
        }));
        toolbar.add(makeButton(CarbonIcons.ZOOM_OUT, "zoomOut", "Zoom out", (e) -> {
            DatalogPage activePage = getParent().getActivePage();
            if (activePage != null) {
                activePage.zoomOut();
            }
        }));
        toolbar.addSeparator();

        toolbar.add(Box.createHorizontalGlue());
        toolbar.add(tLabel = Labels.text(CarbonIcons.ARROWS_HORIZONTAL, Fonts.VALUE_FONT, ""));
        tLabel.setVisible(false);
    }

    public void setT(long millis) {
        float seconds = (millis / 1000.0f);
        tLabel.setText(String.format("t=%.2fs ", seconds)); // Space is not a typo; just to align
        tLabel.setVisible(millis > 0);
    }

    public void setPaused(boolean paused) {

        boolean recording = getParent().isRecording();
        if (recording) {
            pauseButton.setIcon(Icons.get(CarbonIcons.STOP_FILLED, BUTTON_ICON_SIZE));
        } else {
            pauseButton.setIcon(Icons.get(CarbonIcons.RECORDING_FILLED, BUTTON_ICON_SIZE));
        }

        if (paused) {
            pauseButton.setToolTipText("Record new datalog");
        } else {
            pauseButton.setToolTipText("Stop recording");
        }
    }
}
