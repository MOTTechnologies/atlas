package com.github.manevolent.atlas.ui.component.table;

import com.github.manevolent.atlas.graphics.Model;
import com.github.manevolent.atlas.graphics.Point3F;
import com.github.manevolent.atlas.model.Calibration;
import com.github.manevolent.atlas.model.MemorySource;
import com.github.manevolent.atlas.model.Series;
import com.github.manevolent.atlas.model.Table;
import com.github.manevolent.atlas.ui.Editor;
import com.github.manevolent.atlas.ui.component.AtlasComponent;
import com.github.manevolent.atlas.ui.util.Fonts;
import com.github.manevolent.atlas.ui.util.Layout;
import com.jogamp.opengl.*;
import com.jogamp.opengl.awt.GLJPanel;
import com.jogamp.opengl.glu.GLU;
import com.jogamp.opengl.util.awt.TextRenderer;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.IOException;
import java.util.ArrayList;

import static com.github.manevolent.atlas.model.Axis.X;
import static com.github.manevolent.atlas.model.Axis.Y;
import static com.jogamp.opengl.GL.GL_MULTISAMPLE;

public class TableStackedVisualizer extends TableVisualizer {
    private static final Color wireColor = new Color(32, 32, 32);
    private static final Color axisColor = new Color(128, 128, 128);

    private final GLU glu = new GLU();

    private boolean needsUpdate = false;

    private Model primaryModel;

    private final Object renderLock = new Object();

    protected TableStackedVisualizer(TableEditor editor) {
        super(editor, CarbonIcons.CHART_MULTI_LINE, "Stacked");
    }

    @Override
    public Editor getEditor() {
        return getParent().getEditor();
    }

    public void dataChanged() {
        if (!needsUpdate) {
            needsUpdate = true;
            SwingUtilities.invokeLater(() -> {
                getComponent().repaint();
            });
        }
    }

    private void updateModels(GL2 gl) throws IOException {
        updateTableModel(gl);
    }

    private void updateTableModel(GL2 gl) throws IOException {
        Calibration calibration = getCalibration();
        if (calibration == null) {
            return;
        }

        Table table = getTable();
        Series data = table.getData();
        float min = data.getMin(calibration), max = data.getMax(calibration);

        Series x_series = table.getSeries(X);
        float x_min, x_max;
        if (x_series != null) {
            x_min = x_series.getMin(calibration);
            x_max = x_series.getMax(calibration);
        } else {
            x_min = 0;
            x_max = 1;
        }

        Series y_series = table.getSeries(Y);

        int x_length = x_series != null ? x_series.getLength() : 1;
        int y_length = y_series != null ? y_series.getLength() : 1;
        float size = Math.max(x_length, y_length);

        if (primaryModel == null || primaryModel.isDisposed()) {
            primaryModel = Model.genModel(gl, GL2.GL_LINES);
        }

        primaryModel.beginVertices();
        for (int y = 0; y < y_length; y ++) {
            for (int x = 1; x < x_length; x ++) {
                dataVertex(primaryModel, calibration,
                        x - 1, x_length, x_min, x_max,
                        y, y_length,
                        min, max);

                dataVertex(primaryModel, calibration,
                        x, x_length, x_min, x_max,
                        y, y_length,
                        min, max);
            }
        }
        primaryModel.endVertices(gl);

        needsUpdate = false;
    }

    @Override
    public void init(GLAutoDrawable g) {
        synchronized (renderLock) {
            JPanel panel = getComponent();
            Color background = panel.getBackground();

            final GL2 gl = g.getGL().getGL2();

            gl.glLoadIdentity();

            try {
                updateModels(gl);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

            gl.glClearColor(background.getRed() / 255f,
                    background.getGreen() / 255f,
                    background.getBlue() / 255f,
                    background.getAlpha() / 255f);

            gl.glShadeModel(GL2.GL_SMOOTH);
            gl.glClearDepth(1.0f);
            gl.glEnable(GL2.GL_DEPTH_TEST);
            gl.glDepthFunc(GL2.GL_LEQUAL);
            gl.glHint(GL2.GL_PERSPECTIVE_CORRECTION_HINT, GL2.GL_NICEST);
            gl.glEnable(GL_MULTISAMPLE);
        }
    }

    @Override
    public void dispose(GLAutoDrawable g) {
        synchronized (renderLock) {
            GL2 gl = g.getGL().getGL2();

            if (primaryModel != null) {
                primaryModel.dispose(gl);
            }
        }
    }

    private void dataVertex(Model model, MemorySource source,
                            int x, int x_length, float x_min, float x_max,
                            int y, int y_length,
                            float min, float max) throws IOException {
        Table table = getTable();
        Series x_axis = table.getSeries(X);
        Series y_axis = table.getSeries(Y);

        float size = Math.max(x_length, y_length);

        int safe_x = Math.max(0, Math.min(x_length - 1, x));
        int safe_y = Math.max(0, Math.min(y_length - 1, y));

        float value;
        try {
            value = table.getCell(getCalibration(), safe_x, safe_y);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        float x_value, y_value;
        if (x_axis != null) {
            x_value = x_axis.get(source, safe_x);
        } else {
            x_value = x;
        }

        Color color = getParent().scaleValueColor(value);

        float scaledValue = ratio(min, value, max);
        if (Float.isNaN(scaledValue)) {
            scaledValue = 0f;
        }

        float x_ratio = ratio(x_min, x_value, x_max);

        model.addVertex(
                new Point3F(x_ratio, scaledValue, 0F),
                new Point3F(color)
        );
    }

    private float ratio(float min, float value, float max) {
        float distance = max - min;
        return (value - min) / distance;
    }

    @Override
    public void display(GLAutoDrawable g) {
        synchronized (renderLock) {
            Table table = getTable();
            Series x_series = table.getSeries(X);
            Series y_series = table.getSeries(Y);

            GLJPanel panel = getComponent();
            GL2 gl = g.getGL().getGL2();

            if (primaryModel == null || primaryModel.isDisposed()) {
                needsUpdate = true;
            }

            if (needsUpdate) {
                try {
                    updateTableModel(gl);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }

            gl.glClear(GL2.GL_COLOR_BUFFER_BIT | GL2.GL_DEPTH_BUFFER_BIT);
            gl.glDisable(GL2.GL_DEPTH_TEST);
            gl.glMatrixMode(GL2.GL_PROJECTION);

            int x_length = x_series != null ? x_series.getLength() : 1;
            int y_length = y_series != null ? y_series.getLength() : 1;
            float size = Math.max(x_length, y_length);

            float x_ratio = x_length / size;
            float y_ratio = y_length / size;
            gl.glLineWidth(2f);

            gl.glPushMatrix();
            gl.glScalef(1.8f, 1.8f, 1f);
            gl.glTranslatef(-0.5f, -0.5f, 0f);

            gl.glColor3f(axisColor.getRed() / 255f, axisColor.getGreen() / 255f, axisColor.getBlue() / 255f);
            gl.glBegin(GL2.GL_LINES);
            gl.glVertex3f(0f, 0f, 0f);
            gl.glVertex3f(1f, 0f, 0f);

            gl.glVertex3f(0f, 0f, 0f);
            gl.glVertex3f(0f, 1f, 0f);
            gl.glEnd();

            primaryModel.render(gl);
            gl.glPopMatrix();

            gl.glFlush();
        }
    }

    @Override
    public void reshape(GLAutoDrawable g, int x, int y, int width, int height) {
        final GL2 gl = g.getGL().getGL2();
        gl.glViewport(0, 0, width, height);
    }

    @Override
    public void mouseClicked(MouseEvent e) {

    }

    @Override
    public void mousePressed(MouseEvent e) {

    }

    @Override
    public void mouseReleased(MouseEvent e) {

    }

    @Override
    public void mouseEntered(MouseEvent e) {

    }

    @Override
    public void mouseExited(MouseEvent e) {

    }

    @Override
    public void mouseWheelMoved(MouseWheelEvent e) {

    }

    @Override
    public void mouseDragged(MouseEvent e) {

    }

    @Override
    public void mouseMoved(MouseEvent e) {

    }
}
