package com.github.manevolent.atlas.ui.component.table;

import com.github.manevolent.atlas.graphics.Model;
import com.github.manevolent.atlas.graphics.Point3F;
import com.github.manevolent.atlas.model.*;
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
import java.awt.Color;
import java.awt.event.*;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.util.ArrayList;

import static com.github.manevolent.atlas.model.Axis.X;
import static com.github.manevolent.atlas.model.Axis.Y;
import static com.jogamp.opengl.GL.GL_MULTISAMPLE;

public class Table3DVisualizer extends TableVisualizer
        implements MouseListener, MouseWheelListener, GLEventListener, MouseMotionListener {
    private static final float fontSize = 16.0f;
    private static final float heightScale = 0.5f;
    private static final float axisSteps = 0.10f;
    private static final Color wireColor = new Color(32, 32, 32);
    private static final Color axisColor = new Color(128, 128, 128);

    private final GLU glu = new GLU();

    private boolean needsTableUpdate = false;
    private boolean needsAxisUpdate = false;

    private TextRenderer renderer;

    private Model primaryModel;
    private Model wireModel;

    private Model axisModel_bottom;
    private Model axisModel_back;
    private Model axisModel_back_left;

    private float y_rotation;
    private float x_rotation;
    private float scale = 1f;

    private Point pressedMousePosition;
    private Point previousMousePosition;
    private float fontScaleFactor;

    private final Object renderLock = new Object();

    private java.util.List<Label> xLabels = new ArrayList<>();
    private java.util.List<Label> yLabels = new ArrayList<>();
    private java.util.List<Label> vLabels = new ArrayList<>();

    protected Table3DVisualizer(TableEditor editor) {
        super(editor, CarbonIcons.CUBE_VIEW, "3D");
    }

    @Override
    public Editor getEditor() {
        return getParent().getEditor();
    }

    @Override
    protected void initComponent(GLJPanel component) {
        super.initComponent(component);

        // Set up initial rotations
        x_rotation = 30f;
        Table table = getTable();
        if (table.hasAxis(Y)) {
            y_rotation = -45f + 360f;
        }
    }

    public void dataChanged() {
        if (!needsTableUpdate || !needsAxisUpdate) {
            needsTableUpdate = needsAxisUpdate = true;
            SwingUtilities.invokeLater(() -> {
                getComponent().repaint();
            });
        }
    }

    private void updateModels(GL2 gl) throws IOException {
        updateTableModel(gl);
        updateAxisModels(gl);
    }

    private void updateTableModel(GL2 gl) throws IOException {
        Calibration calibration = getCalibration();
        if (calibration == null) {
            return;
        }

        Table table = getTable();
        Series data = table.getData();

        float min, max;
        if (data.getAddress().getSection().getMemoryType() == MemoryType.CODE) {
            min = data.getMinPreferred(getCalibration());
            max = data.getMaxPreferred(getCalibration());
        } else {
            min = max = data.getScale().forward(0x00);
        }

        Series x_series = table.getSeries(X);
        float x_min, x_max;
        if (x_series != null) {
            x_min = x_series.getMinPreferred(calibration);
            x_max = x_series.getMaxPreferred(calibration);
        } else {
            x_min = 0;
            x_max = 1;
        }
        Series y_series = table.getSeries(Y);
        float y_min, y_max;
        if (y_series != null) {
            y_min = y_series.getMinPreferred(calibration);
            y_max = y_series.getMaxPreferred(calibration);
        } else {
            y_min = 0;
            y_max = 1;
        }

        int x_length = x_series != null ? x_series.getLength() : 1;
        int y_length = y_series != null ? y_series.getLength() : 1;
        float size = Math.max(x_length, y_length);

        if (primaryModel == null || primaryModel.isDisposed()) {
            primaryModel = Model.genModel(gl, GL2.GL_QUADS);
        }
        if (wireModel == null || wireModel.isDisposed()) {
            wireModel = Model.genModel(gl, GL2.GL_LINES);
        }

        primaryModel.beginVertices();
        wireModel.beginVertices();

        for (int x = 0; x < x_length; x ++) {
            for (int y = 0; y < y_length; y ++) {
                dataQuad(primaryModel, calibration,
                        x, x_length, x_min, x_max,
                        y, y_length, y_min, y_max,
                        min, max, null);

                dataWire(wireModel, calibration,
                        x, x_length, x_min, x_max,
                        y, y_length, y_min, y_max,
                        min, max, wireColor);
            }
        }

        primaryModel.endVertices(gl);
        wireModel.endVertices(gl);
    }

    private void updateAxisModels(GL2 gl) throws IOException {
        Calibration calibration = getCalibration();
        if (calibration == null) {
            return;
        }

        Table table = getTable();
        Series data = table.getData();

        Series x_series = table.getSeries(X);
        Series y_series = table.getSeries(Y);

        int x_length = x_series != null ? x_series.getLength() : 1;
        int y_length = y_series != null ? y_series.getLength() : 1;
        float size = Math.max(x_length, y_length);

        float x_axis_ratio = x_length / size;
        float y_axis_ratio = y_length / size;
        float v_axis_ratio = heightScale;

        float steps = axisSteps * (1 / scale);
        int x_axis_length = (int) Math.max(2, Math.min(16, Math.ceil(x_axis_ratio / steps))) - 1;
        int y_axis_length = (int) Math.max(2, Math.min(16, Math.ceil(y_axis_ratio / steps))) - 1;
        int v_axis_length = (int) Math.max(2, Math.min(16, Math.ceil(v_axis_ratio / steps))) - 1;

        // bottom
        if (axisModel_bottom == null || axisModel_bottom.isDisposed()) {
            axisModel_bottom = Model.genModel(gl, GL2.GL_LINES);
        }
        axisModel_bottom.beginVertices();
        xLabels.clear();
        for (int x = 0; x <= x_axis_length; x ++) {
            float x_ratio = (x / (float)x_axis_length);
            float pos_x = x_ratio * x_axis_ratio;
            float pos_y = 0;
            Point3F origin = new Point3F(pos_x, pos_y, 0);
            axisModel_bottom.addVertex(origin, new Point3F(axisColor));
            axisModel_bottom.addVertex(new Point3F(pos_x, pos_y, y_axis_ratio), new Point3F(axisColor));
            if (x_series != null && x > 0 && x < x_axis_length) {
                xLabels.add(new Label(x_series.format(calibration, x_ratio), origin));
            }
        }
        yLabels.clear();
        for (int y = 0; y <= y_axis_length; y ++) {
            float y_ratio = (y / (float)y_axis_length);
            float pos_y = 0;
            float pos_z = y_ratio * y_axis_ratio;
            Point3F origin = new Point3F(0, pos_y, pos_z);
            axisModel_bottom.addVertex(origin, new Point3F(axisColor));
            axisModel_bottom.addVertex(new Point3F(x_axis_ratio, pos_y, pos_z), new Point3F(axisColor));
            if (y_series != null && y > 0 && y < y_axis_length) {
                yLabels.add(new Label(y_series.format(calibration, y_ratio), origin));
            }
        }
        axisModel_bottom.endVertices(gl);

        // back
        if (axisModel_back == null || axisModel_back.isDisposed()) {
            axisModel_back = Model.genModel(gl, GL2.GL_LINES);
        }
        vLabels.clear();
        axisModel_back.beginVertices();
        float v_min = getParent().getMin();
        float v_max = getParent().getMax();
        for (int v = 0; v <= v_axis_length; v ++) {
            float v_ratio = (v / (float)v_axis_length);
            float pos_y = v_ratio * v_axis_ratio;
            float pos_z = 0;
            Point3F origin = new Point3F(0, pos_y, pos_z);
            axisModel_back.addVertex(origin, new Point3F(axisColor));
            axisModel_back.addVertex(new Point3F(x_axis_ratio, pos_y, pos_z), new Point3F(axisColor));
            if (v > 0) {
                float v_ranged = v_min + ((v_max - v_min) * v_ratio);
                vLabels.add(new Label(data.getScale().format(v_ranged), origin));
            }
        }
        for (int x = 0; x <= x_axis_length; x ++) {
            float pos_x = (x / (float)x_axis_length) * x_axis_ratio;
            float pos_z = 0;
            axisModel_back.addVertex(new Point3F(pos_x, 0, pos_z), new Point3F(axisColor));
            axisModel_back.addVertex(new Point3F(pos_x, v_axis_ratio, pos_z), new Point3F(axisColor));
        }
        axisModel_back.endVertices(gl);

        // back left
        if (axisModel_back_left == null || axisModel_back_left.isDisposed()) {
            axisModel_back_left = Model.genModel(gl, GL2.GL_LINES);
        }
        axisModel_back_left.beginVertices();
        for (int v = 0; v <= v_axis_length; v ++) {
            float pos_x = 0;
            float pos_y = (v / (float)v_axis_length) * v_axis_ratio;
            axisModel_back_left.addVertex(new Point3F(pos_x, pos_y, 0), new Point3F(axisColor));
            axisModel_back_left.addVertex(new Point3F(pos_x, pos_y, y_axis_ratio), new Point3F(axisColor));
        }
        for (int y = 0; y <= y_axis_length; y ++) {
            float pos_x = 0;
            float pos_z = (y / (float)y_axis_length) * y_axis_ratio;
            axisModel_back_left.addVertex(new Point3F(pos_x, 0, pos_z), new Point3F(axisColor));
            axisModel_back_left.addVertex(new Point3F(pos_x, v_axis_ratio, pos_z), new Point3F(axisColor));
        }
        axisModel_back_left.endVertices(gl);
    }

    @Override
    public void init(GLAutoDrawable g) {
        synchronized (renderLock) {
            JPanel panel = getComponent();
            Color background = panel.getBackground();

            final GL2 gl = g.getGL().getGL2();

            gl.glLoadIdentity();

            Font renderFont = Fonts.VALUE_FONT.deriveFont(fontSize);
            renderer = new TextRenderer(renderFont);
            fontScaleFactor = (1f / fontSize) * (1f / 32f);

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
            renderer.dispose();

            GL2 gl = g.getGL().getGL2();

            if (primaryModel != null) {
                primaryModel.dispose(gl);
            }
            if (wireModel != null) {
                wireModel.dispose(gl);
            }

            if (axisModel_bottom != null) {
                axisModel_bottom.dispose(gl);
            }
            if (axisModel_back != null) {
                axisModel_back.dispose(gl);
            }
            if (axisModel_back_left != null) {
                axisModel_back_left.dispose(gl);
            }
        }
    }

    private void dataWire(Model model, MemorySource source,
                          int x, int x_length, float x_min, float x_max,
                          int y, int y_length, float y_min, float y_max,
                          float min, float max,
                          Color color) throws IOException {
        dataVertex(model, source,
                x, x_length, x_min, x_max,
                y, y_length, y_min, y_max,
                min, max, color);

        dataVertex(model, source,
                x, x_length, x_min, x_max,
                y + 1, y_length, y_min, y_max,
                min, max, color);


        dataVertex(model, source,
                x, x_length, x_min, x_max,
                y + 1, y_length, y_min, y_max,
                min, max, color);

        dataVertex(model, source,
                x + 1, x_length, x_min, x_max,
                y + 1, y_length, y_min, y_max,
                min, max, color);


        dataVertex(model, source,
                x + 1, x_length, x_min, x_max,
                y + 1, y_length, y_min, y_max,
                min, max, color);

        dataVertex(model, source,
                x + 1, x_length, x_min, x_max,
                y, y_length, y_min, y_max,
                min, max, color);


        dataVertex(model, source,
                x + 1, x_length, x_min, x_max,
                y, y_length, y_min, y_max,
                min, max, color);

        dataVertex(model, source,
                x, x_length, x_min, x_max,
                y, y_length, y_min, y_max,
                min, max, color);
    }

    private void dataQuad(Model model, MemorySource source,
                          int x, int x_length, float x_min, float x_max,
                          int y, int y_length, float y_min, float y_max,
                          float min, float max,
                          Color color) throws IOException {
        dataVertex(model, source,
                x, x_length, x_min, x_max,
                y, y_length, y_min, y_max,
                min, max, color);
        dataVertex(model, source,
                x, x_length, x_min, x_max,
                y + 1, y_length, y_min, y_max,
                min, max, color);
        dataVertex(model, source,
                x + 1, x_length, x_min, x_max,
                y + 1, y_length, y_min, y_max,
                min, max, color);
        dataVertex(model, source,
                x + 1, x_length, x_min, x_max,
                y, y_length, y_min, y_max,
                min, max, color);
    }

    private void dataVertex(Model model, MemorySource source,
                            int x, int x_length, float x_min, float x_max,
                            int y, int y_length, float y_min, float y_max,
                            float min, float max,
                            Color color) throws IOException {
        Table table = getTable();
        Series x_axis = table.getSeries(X);
        Series y_axis = table.getSeries(Y);

        float size = Math.max(x_length, y_length);

        int safe_x = Math.max(0, Math.min(x_length - 1, x));
        int safe_y = Math.max(0, Math.min(y_length - 1, y));

        float value;
        try {
            value = table.getData().getUnit().convertToPreferred(getParent().getValue(safe_x, safe_y));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        float x_value, y_value;
        if (x_axis != null) {
            x_value = x_axis.getUnit().convertToPreferred(x_axis.get(source, safe_x));
        } else {
            x_value = x;
        }
        if (y_axis != null) {
            y_value = y_axis.getUnit().convertToPreferred(y_axis.get(source, safe_y));
        } else {
            y_value = y;
        }

        if (color == null) {
            color = getParent().scaleValueColor(value);
        }

        float scaledValue = ratio(min, value, max);
        if (Float.isNaN(scaledValue)) {
            scaledValue = 0f;
        }

        float x_ratio = ratio(x_min, x_value, x_max);
        float y_ratio = ratio(y_min, y_value, y_max);

        float x_aspect_ratio = x_length / size;
        float y_aspect_ratio = y_length / size;

        model.addVertex(
                new Point3F(x_ratio * x_aspect_ratio, scaledValue * heightScale, y_ratio * y_aspect_ratio),
                new Point3F(color)
        );
    }

    private float ratio(float min, float value, float max) {
        float distance = max - min;
        return (value - min) / distance;
    }

    private void applyCameraRotation(GL2 gl, float x_ratio, float y_ratio) {
        gl.glTranslatef(x_ratio / 2f, 0f, y_ratio / 2f);  // Move right and into the screen
        gl.glRotatef(x_rotation, 1f, 0f, 0f);
        gl.glRotatef(y_rotation, 0f, 1f, 0f);
        gl.glScalef(scale, scale, scale);
        gl.glTranslatef(-(x_ratio / 2f), 0f, -(y_ratio / 2f));  // Move right and into the screen
    }

    private void reverseCameraRotation(GL2 gl, Point3F point3F) {
        gl.glTranslatef(point3F.getX(), point3F.getY(), point3F.getZ());  // Move right and into the screen
        gl.glRotatef(-y_rotation, 0f, 1f, 0f);
        gl.glRotatef(-x_rotation, 1f, 0f, 0f);
        gl.glTranslatef(-point3F.getX(), -point3F.getY(), -point3F.getZ());  // Move right and into the screen
    }

    @Override
    public void display(GLAutoDrawable g) {
        synchronized (renderLock) {
            Table table = getTable();
            Series x_series = table.getSeries(X);
            Series y_series = table.getSeries(Y);

            GLJPanel panel = getComponent();
            GL2 gl = g.getGL().getGL2();

            if (axisModel_bottom == null || axisModel_bottom.isDisposed() ||
                    axisModel_back == null || axisModel_back.isDisposed() ||
                    axisModel_back_left == null || axisModel_back_left.isDisposed()) {
                needsTableUpdate = true;
                needsAxisUpdate = true;
            }

            if (needsTableUpdate) {
                try {
                    updateTableModel(gl);
                    needsTableUpdate = false;
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }

            if (needsAxisUpdate) {
                try {
                    updateAxisModels(gl);
                    needsAxisUpdate = false;
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }

            gl.glClear(GL2.GL_COLOR_BUFFER_BIT | GL2.GL_DEPTH_BUFFER_BIT);
            gl.glMatrixMode(GL2.GL_MODELVIEW);
            gl.glLoadIdentity();

            int x_length = x_series != null ? x_series.getLength() : 1;
            int y_length = y_series != null ? y_series.getLength() : 1;
            float size = Math.max(x_length, y_length);

            float x_ratio = x_length / size;
            float y_ratio = y_length / size;

            gl.glTranslatef(-(x_ratio / 2f), -(heightScale / 2f), -3f);

            applyCameraRotation(gl, x_ratio, y_ratio);

            gl.glLineWidth(1f);
            axisModel_bottom.render(gl);

            gl.glPushMatrix();
            if (y_rotation >= 90f && y_rotation <= 270f) {
                gl.glTranslatef(0f, 0f, y_ratio);
            }
            axisModel_back.render(gl);
            gl.glPopMatrix();

            gl.glPushMatrix();
            if (y_rotation <= 180f) {
                gl.glTranslatef(x_ratio, 0f, 0f);
            }
            axisModel_back_left.render(gl);
            gl.glPopMatrix();

            primaryModel.render(gl);
            wireModel.render(gl);

            renderLabels(gl, x_ratio, y_ratio);

            gl.glFlush();
        }
    }

    private void renderLabels(GL2 gl, float x_ratio, float y_ratio) {
        gl.glClear(GL2.GL_DEPTH_BUFFER_BIT);

        gl.glPushMatrix();
        if (y_rotation <= 90f || y_rotation >= 270f) {
            gl.glTranslatef(0f, 0f, y_ratio);
        }
        xLabels.forEach(label -> label.draw(gl, renderer));
        gl.glPopMatrix();

        gl.glPushMatrix();
        if (y_rotation >= 180f) {
            gl.glTranslatef(x_ratio, 0f, 0f);
        }
        yLabels.forEach(label -> label.draw(gl, renderer));
        gl.glPopMatrix();

        gl.glPushMatrix();
        if (y_rotation >= 270f) {
            gl.glTranslatef(x_ratio, 0f, 0f);
        } else if (y_rotation >= 90f && y_rotation < 180f) {
            gl.glTranslatef(0f, 0f, y_ratio);
        } else if (y_rotation < 90f) {
            gl.glTranslatef(x_ratio, 0f, y_ratio);
        }
        vLabels.forEach(label -> label.draw(gl, renderer));
        gl.glPopMatrix();
    }

    @Override
    public void reshape(GLAutoDrawable g, int x, int y, int width, int height) {
        final GL2 gl = g.getGL().getGL2();
        if(height <= 0) {
            height = 1;
        }

        final float h = (float) width / (float) height;
        gl.glViewport( 0, 0, width, height);
        gl.glMatrixMode(GL2.GL_PROJECTION);
        gl.glLoadIdentity();
        glu.gluPerspective(45.0f, h, 1.0, 20.0);

        gl.glMatrixMode(GL2.GL_MODELVIEW);
        gl.glLoadIdentity();
    }

    @Override
    public void mouseClicked(MouseEvent e) {

    }

    @Override
    public void mousePressed(MouseEvent e) {
        // Transparent 16 x 16 pixel cursor image.
        BufferedImage cursorImg = new BufferedImage(16, 16, BufferedImage.TYPE_INT_ARGB);

// Create a new blank cursor.
        Cursor blankCursor = Toolkit.getDefaultToolkit().createCustomCursor(
                cursorImg, new Point(0, 0), "blank cursor");

        getComponent().setCursor(blankCursor);

        pressedMousePosition = previousMousePosition = e.getLocationOnScreen();
    }

    @Override
    public void mouseReleased(MouseEvent e) {
        getComponent().setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
    }

    @Override
    public void mouseEntered(MouseEvent e) {

    }

    @Override
    public void mouseExited(MouseEvent e) {

    }

    @Override
    public void mouseWheelMoved(MouseWheelEvent e) {
        synchronized (renderLock) {
            scale -= (float) (e.getPreciseWheelRotation() / 10f);
            scale = Math.max(0.1f, Math.min(4f, scale));
        }

        SwingUtilities.invokeLater(() -> {
            needsAxisUpdate = true;
            getComponent().repaint();
        });
    }

    private void moveMouse(Point p) {
        GraphicsEnvironment ge =
                GraphicsEnvironment.getLocalGraphicsEnvironment();
        GraphicsDevice[] gs = ge.getScreenDevices();

        // Search the devices for the one that draws the specified point.
        for (GraphicsDevice device: gs) {
            GraphicsConfiguration[] configurations =
                    device.getConfigurations();
            for (GraphicsConfiguration config: configurations) {
                Rectangle bounds = config.getBounds();
                if(bounds.contains(p)) {
                    // Set point to screen coordinates.
                    Point b = bounds.getLocation();
                    Point s = new Point(p.x - b.x, p.y - b.y);

                    try {
                        Robot r = new Robot(device);
                        r.mouseMove(s.x, s.y);
                    } catch (AWTException e) {
                        e.printStackTrace();
                    }

                    return;
                }
            }
        }
        // Couldn't move to the point, it may be off screen.
        return;
    }

    @Override
    public void mouseDragged(MouseEvent e) {
        if (previousMousePosition == null) {
            previousMousePosition = e.getLocationOnScreen();
        }

        Point traveled = e.getLocationOnScreen();

        x_rotation += (float) (traveled.getY() - previousMousePosition.getY()) / 10f;
        y_rotation -= (float) (traveled.getX() - previousMousePosition.getX()) / 10f;

        x_rotation = Math.max(0f, Math.min(90f, x_rotation));
        while (y_rotation < 0) y_rotation += 360f;
        y_rotation = y_rotation % 360.0f;

        previousMousePosition = pressedMousePosition;

        moveMouse(pressedMousePosition);

        getComponent().repaint();
    }

    @Override
    public void mouseMoved(MouseEvent e) {

    }

    private class Label {
        private final String text;
        private final Point3F point;

        private Label(String text, Point3F point) {
            this.text = text;
            this.point = point;
        }

        public String getText() {
            return text;
        }

        public Point3F getPoint() {
            return point;
        }

        public void draw(GL2 gl, TextRenderer renderer) {
            gl.glPushMatrix();

            reverseCameraRotation(gl, point);

            renderer.begin3DRendering();
            renderer.draw3D(text,
                    point.getX(), point.getY(), point.getZ(),
                    fontScaleFactor);
            renderer.end3DRendering();

            gl.glPopMatrix();
        }
    }
}
