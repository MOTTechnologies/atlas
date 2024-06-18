package com.github.manevolent.atlas.ui.component.menu.editor;

import com.github.manevolent.atlas.model.*;
import com.github.manevolent.atlas.ui.Editor;
import com.github.manevolent.atlas.ui.component.calibration.*;
import com.github.manevolent.atlas.ui.dialog.ProgressDialog;
import com.github.manevolent.atlas.ui.util.Errors;
import com.github.manevolent.atlas.ui.util.Layout;
import com.github.manevolent.atlas.ui.util.Menus;
import com.github.manevolent.atlas.ui.util.Tools;
import org.checkerframework.checker.units.qual.A;
import org.checkerframework.checker.units.qual.Area;
import org.kordamp.ikonli.carbonicons.CarbonIcons;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.swing.*;
import javax.swing.event.AncestorEvent;
import javax.swing.event.AncestorListener;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class CalibrationMenu extends EditorMenu {
    public CalibrationMenu(Editor editor) {
        super(editor);
    }

    @Override
    protected void initComponent(JMenu menu) {
        menu.setText("Calibration");

        menu.add(Menus.item(CarbonIcons.CHIP, "Flash Calibration...", this::flashCalibration));
        menu.add(Menus.item(CarbonIcons.DOWNLOAD, "Read New Calibration...", this::readCalibration));

        menu.addSeparator();

        menu.add(Menus.item(CarbonIcons.FETCH_UPLOAD, "Apply Other Calibration...", this::applyCalibration));
    }

    private void applyCalibration(ActionEvent event) {
        Editor editor = getEditor();
        Tools.applyCalibration(editor, x -> true);
    }

    private void readCalibration(ActionEvent event) {
        //TODO
    }

    private void flashCalibration(ActionEvent event) {
        getEditor().flashCalibration();
    }

}
