package com.github.manevolent.atlas.ui.component.table;

import com.github.manevolent.atlas.model.Calibration;
import com.github.manevolent.atlas.model.Table;
import com.github.manevolent.atlas.ui.component.AtlasComponent;
import com.github.manevolent.atlas.ui.util.*;
import com.jogamp.opengl.GLCapabilities;
import com.jogamp.opengl.GLEventListener;
import com.jogamp.opengl.GLProfile;
import com.jogamp.opengl.awt.GLJPanel;
import org.kordamp.ikonli.Ikon;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseListener;
import java.awt.event.MouseMotionListener;
import java.awt.event.MouseWheelListener;

public abstract class TableVisualizer extends AtlasComponent<GLJPanel, TableEditor>
        implements MouseListener, MouseWheelListener, GLEventListener, MouseMotionListener {
    private static final Font labelFont = Fonts.getTextFont();
    private final Ikon icon;
    private final String name;

    protected TableVisualizer(TableEditor editor, Ikon icon, String name) {
        super(editor);
        this.icon = icon;
        this.name = name;
    }

    protected Table getTable() {
        return getParent().getTable();
    }

    protected Calibration getCalibration() {
        return getParent().getCalibration();
    }

    @Override
    protected GLJPanel newComponent() {
        GLProfile profile = GLProfile.get(GLProfile.GL2);
        GLCapabilities glcapabilities = new GLCapabilities(profile);

        glcapabilities.setBackgroundOpaque(true);
        glcapabilities.setDoubleBuffered(true);
        glcapabilities.setSampleBuffers(true);
        glcapabilities.setNumSamples(2);

        GLJPanel panel = new GLJPanel(glcapabilities) { };

        panel.setBackground(panel.getBackground().darker());
        panel.setMinimumSize(new Dimension(0, 0));
        panel.addGLEventListener(this);
        panel.addMouseListener(this);
        panel.addMouseWheelListener(this);
        panel.addMouseMotionListener(this);
        Layout.emptyBorder(panel);

        return panel;
    }

    @Override
    protected void initComponent(GLJPanel component) {
        component.setLayout(new BorderLayout());
        JPanel top = Layout.emptyBorder(5, 5, 5, 5, new JPanel(new BorderLayout()));
        top.add(Labels.text(icon, name), BorderLayout.CENTER);
        top.setBackground(Colors.withAlpha(Color.BLACK, 64));
        component.add(top, BorderLayout.NORTH);
        component.add(Box.createVerticalGlue(), BorderLayout.CENTER);
    }
}
