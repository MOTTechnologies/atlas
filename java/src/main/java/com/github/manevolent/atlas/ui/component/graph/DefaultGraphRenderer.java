package com.github.manevolent.atlas.ui.component.graph;

import com.github.manevolent.atlas.connection.MemoryFrame;
import com.github.manevolent.atlas.logging.Log;
import com.github.manevolent.atlas.model.node.*;
import com.github.manevolent.atlas.settings.Settings;
import com.github.manevolent.atlas.ui.behavior.ChangeType;
import com.github.manevolent.atlas.ui.behavior.Model;
import com.github.manevolent.atlas.ui.util.Colors;

import javax.swing.*;
import javax.swing.event.AncestorEvent;
import javax.swing.event.AncestorListener;
import java.awt.*;

import java.awt.event.*;
import java.awt.geom.Ellipse2D;
import java.awt.geom.Path2D;
import java.util.*;
import java.util.List;
import java.util.logging.Level;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class DefaultGraphRenderer extends GraphComponent implements GraphRenderer, ComponentListener {
    private static final int emptyBufferSpace = 512;
    private static final Color backgroundColor = new Color(0x303030);
    private static final int hoverZoneSize = 10;

    public static final int gridSize = 128;
    public static final int gridCells = 4;

    private final Map<GraphNode, DefaultNodeComponent> nodes = new HashMap<>();
    private final GraphEditor page;

    private final GraphModule module;

    private DefaultEndpointComponent pressedEndpoint;
    private DefaultEndpointComponent hoveredEndpoint;
    private NodeConnection hoveredConnection;

    private List<NodeComponent> visibleNodes = new ArrayList<>();
    private List<NodeConnection> visibleConnections = new ArrayList<>();

    public DefaultGraphRenderer(GraphEditor page, GraphModule module) {
        this.page = page;
        this.module = module;

        setOpaque(true);
        setBackground(backgroundColor);
        setLayout(null);

        addMouseMotionListener(new MouseAdapter() {
            @Override
            public void mouseMoved(MouseEvent e) {
                DefaultGraphRenderer.this.mouseMoved(e);
            }

            @Override
            public void mouseDragged(MouseEvent e) {
                DefaultGraphRenderer.this.mouseDragged(e);
            }
        });

        addContainerListener(new ContainerAdapter() {
            @Override
            public void componentAdded(ContainerEvent e) {
                e.getChild().addComponentListener(DefaultGraphRenderer.this);
                updateVisibleNodes();
            }

            @Override
            public void componentRemoved(ContainerEvent e) {
                e.getChild().removeComponentListener(DefaultGraphRenderer.this);
                updateVisibleNodes();
            }
        });

        addAncestorListener(new AncestorListener() {
            @Override
            public void ancestorAdded(AncestorEvent event) {
                updateBounds();
            }

            @Override
            public void ancestorRemoved(AncestorEvent event) {

            }

            @Override
            public void ancestorMoved(AncestorEvent event) {

            }
        });
    }

    @Override
    public java.util.List<NodeComponent> updateVisibleNodes() {
        if (isShowing()) {
            Dimension size = getVisibleRect().getSize();
            this.visibleNodes = GraphRenderer.super.getVisibleComponents().toList();
            this.visibleConnections = getConnections().stream().filter(c -> isConnectionVisible(c, size)).toList();
        } else {
            this.visibleNodes = new ArrayList<>();
            this.visibleConnections = new ArrayList<>();
        }

        return this.visibleNodes;
    }

    @Override
    public Stream<NodeComponent> getVisibleComponents() {
        return visibleNodes.stream();
    }

    public GraphEditor getPage() {
        return page;
    }

    public DefaultEndpointComponent getHoveredEndpoint() {
        return hoveredEndpoint;
    }

    private Cursor getCursorToUse() {
        boolean hand = hoveredEndpoint != null || pressedEndpoint != null || hoveredConnection != null;
        return Cursor.getPredefinedCursor(hand ? Cursor.HAND_CURSOR : Cursor.DEFAULT_CURSOR);
    }

    private void updateCursor() {
        setCursor(getCursorToUse());
    }

    /**
     * Sets the currently hovered endpoint.
     * @param endpoint endpoint being hovered.
     */
    public boolean setHoveredEndpoint(DefaultEndpointComponent endpoint) {
        if (this.hoveredEndpoint != endpoint) {
            this.hoveredEndpoint = endpoint;

            // Set the cursor if anything is hovered
            updateCursor();

            repaint();
            return true;
        } else {
            return false;
        }
    }

    /**
     * Sets the currently hovered connection.
     * @param connection hovered connection, or null if no connection is being hovered over.
     */
    public boolean setHoveredConnection(NodeConnection connection) {
        if (this.hoveredConnection != connection) {
            this.hoveredConnection = connection;

            // Set the cursor if anything is hovered
            updateCursor();

            repaint();
            return true;
        } else {
            return false;
        }
    }

    /**
     * Gets the currently pressed endpoint.
     * @return pressed endpoint, or null if no endpoint is pressed.
     */
    public DefaultEndpointComponent getPressedEndpoint() {
        return pressedEndpoint;
    }

    /**
     * Finds an endpoint component from a given graph node and its corresponding endpoint
     * @param graphNode graph node to search on
     * @param endpoint endpoint to find on the graph node provided
     * @return endpoint component found, null otherwise.
     */
    public DefaultEndpointComponent getEndpointComponent(GraphNode graphNode, NodeEndpoint<?> endpoint) {
        return nodes.get(graphNode).getEndpointComponent(endpoint);
    }

    /**
     * Sets the currently pressed endpoint. This is primarily used to draw the temporarily-dragged connection lines.
     * @param endpoint pressed endpoint, or null if no endpoint is pressed.
     */
    public boolean setPressedEndpoint(DefaultEndpointComponent endpoint) {
        if (this.pressedEndpoint != endpoint) {
            if (endpoint == null && hoveredEndpoint != null && hoveredEndpoint != pressedEndpoint) {
                NodeConnection connection;
                try {
                    // We should create a new connection!
                    connection = pressedEndpoint.getGraphNode().createConnection(
                            pressedEndpoint.getEndpoint(),
                            hoveredEndpoint.getGraphNode(),
                            hoveredEndpoint.getEndpoint());

                    // Ensure these can be called
                    connection.getInput();
                    connection.getOutput();

                    page.addConnection(connection);
                    onNodeChanged();
                } catch (Exception ex) {
                    Log.ui().log(Level.WARNING, "Problem creating node connection", ex);
                }

                this.pressedEndpoint = null;
            } else if (endpoint != null && endpoint.getEndpoint() instanceof NodeInput<?> input) {
                // Try to detach this endpoint if it was already connected
                NodeConnection connection = getVisibleConnections().stream()
                        .filter(c -> c.getTarget() == endpoint.getGraphNode() && c.getInput() == input)
                        .findFirst().orElse(null);

                if (connection != null) {
                    this.pressedEndpoint = getEndpointComponent(connection.getSource(), connection.getOutput());
                    page.removeConnection(connection);
                    onNodeChanged();
                } else {
                    this.pressedEndpoint = endpoint;
                }
            } else {
                this.pressedEndpoint = endpoint;
            }

            updateHoveredConnection();

            // Set the cursor if anything is hovered
            updateCursor();

            repaint();

            return true;
        } else {
            return false;
        }
    }

    private void mouseDragged(MouseEvent e) {
        repaint();
    }

    private void mouseMoved(MouseEvent e) {
        if (e.getButton() == MouseEvent.NOBUTTON) {
            updateHoveredConnection();
        } else {
            setHoveredConnection(null);
        }
    }

    @Override
    public Point getGraphMousePosition() {
        return getMousePosition();
    }

    private void updateHoveredConnection() {
        if (pressedEndpoint != null) {
            setHoveredConnection(null);
            return;
        }

        NodeConnection hoveredConnection = getVisibleConnections().stream()
                .filter(this::isHovered)
                .min(Comparator.comparingDouble(this::distanceToClosestAnchor))
                .orElse(null);

        setHoveredConnection(hoveredConnection);
    }

    @Override
    public void doLayout() {
        for (Component component : getComponents()) {
            component.doLayout();
        }
    }

    @Override
    public void setBounds(int x, int y, int width, int height) {
        super.setBounds(x, y, width, height);
        doLayout();
    }

    @Override
    public NodeComponent getComponent(GraphNode node) {
        return nodes.get(node);
    }

    @Override
    public List<NodeComponent> getNodeComponents() {
        return Arrays.stream(getComponents()).map(c -> (NodeComponent) c).toList();
    }

    @Override
    public DefaultNodeComponent createComponent(GraphNode node) {
        DefaultNodeComponent component = new DefaultNodeComponent(node, this);
        this.add(component);
        nodes.put(node, component);
        component.revalidate();
        updateVisibleNodes();
        return component;
    }

    @Override
    public void deleteComponent(NodeComponent component) {
        if (component instanceof DefaultNodeComponent defaultNodeComponent) {
            this.remove(defaultNodeComponent);
            nodes.remove(component.getGraphNode());
            updateVisibleNodes();
            repaint();
        }
    }

    @Override
    public void reset() {
        hoveredConnection = null;
        pressedEndpoint = null;
        hoveredEndpoint = null;

        repaint();
    }

    @Override
    public GraphComponent createRenderTarget() {
        return this;
    }

    private Point screenToRelative(Point screenLocation) {
        if (screenLocation == null) {
            return null;
        }

        Point locationOnScreen = getLocationOnScreen();
        if (locationOnScreen == null) {
            return null;
        }

        return new Point(
                screenLocation.x - locationOnScreen.x,
                screenLocation.y - locationOnScreen.y
        );
    }

    private double distanceToClosestAnchor(NodeConnection connection) {
        NodeComponent component = nodes.get(connection.getSource());
        NodeComponent other = nodes.get(connection.getTarget());

        Point mousePosition = getMousePosition();
        if (component == null || other == null || mousePosition == null) {
            return Double.MAX_VALUE; // infinitely far lol
        }

        Point source = screenToRelative(component.getOutputAnchorPoint(connection.getOutput()));
        Point target = screenToRelative(other.getInputAnchorPoint(connection.getInput()));

        double distanceToSource = mousePosition.distance(source);
        double distanceToTarget = mousePosition.distance(target);

        return Math.min(distanceToSource, distanceToTarget);
    }

    private boolean isHovered(NodeConnection connection) {
        DefaultNodeComponent component = nodes.get(connection.getSource());
        DefaultNodeComponent other = nodes.get(connection.getTarget());

        if (component == null || other == null) {
            return false;
        }

        Point mousePosition = getMousePosition();
        Point source = screenToRelative(component.getOutputAnchorPoint(connection.getOutput()));
        Point target = screenToRelative(other.getInputAnchorPoint(connection.getInput()));

        Rectangle bounds = createRectangle(source, target);
        if (mousePosition == null || !bounds.contains(mousePosition)) {
            return false;
        }

        double distance_x = Math.abs(source.x - target.x);
        Path2D cursorPath = new Path2D.Float();
        cursorPath.moveTo(source.x, source.y - hoverZoneSize);
        cursorPath.curveTo(
                source.x + (distance_x / 2), source.y - hoverZoneSize,
                target.x - (distance_x / 2), target.y - hoverZoneSize,
                target.x, target.y - hoverZoneSize
        );
        cursorPath.lineTo(target.x, target.y + hoverZoneSize);
        cursorPath.curveTo(
                target.x - (distance_x / 2), target.y + hoverZoneSize,
                source.x + (distance_x / 2), source.y + hoverZoneSize,
                source.x, source.y + hoverZoneSize
        );
        cursorPath.lineTo(source.x, source.y - hoverZoneSize);

        return cursorPath.contains(mousePosition);
    }

    private void paintConnection(Graphics2D g2d, NodeConnection connection, boolean hovered) {
        NodeComponent component = nodes.get(connection.getSource());
        NodeComponent other = nodes.get(connection.getTarget());

        if (component == null || other == null) {
            return;
        }

        Point source = screenToRelative(component.getOutputAnchorPoint(connection.getOutput()));
        Point target = screenToRelative(other.getInputAnchorPoint(connection.getInput()));

        paintConnection(g2d, source, target, connection.getOutput().getColorUnchecked(connection.getSource()), hovered);
    }

    private void paintConnection(Graphics2D g2d, Point source, Point target, Color color, boolean hovered) {
        if (source == null || target == null) {
            return;
        }

        double distance_x = Math.abs(source.x - target.x);

        if (hovered) {
            g2d.setStroke(new BasicStroke(4f));
        } else {
            g2d.setStroke(new BasicStroke(3f));
            color = Colors.withAlpha(color, 128);
        }

        g2d.setColor(color);

        Path2D path = new Path2D.Float();
        path.append(new Ellipse2D.Float(source.x - 2, source.y - 2, 4, 4), false);
        path.moveTo(source.x, source.y);
        path.curveTo(
                source.x + (distance_x / 2), source.y,
                target.x - (distance_x / 2), target.y,
                target.x, target.y
        );
        path.append(new Ellipse2D.Float(target.x - 2, target.y - 2, 4, 4), false);
        path.moveTo(target.x, target.y);

        g2d.draw(path);
    }

    public boolean isConnectionVisible(NodeConnection connection, Dimension viewportSize) {
        List<NodeComponent> visible = this.visibleNodes;

        NodeComponent source = getComponent(connection.getSource());
        NodeComponent target = getComponent(connection.getTarget());

        if (source == null || target == null) {
            return false;
        }

        if (visible.contains(source) || visible.contains(target)) {
            return true;
        }

        Point sourcePoint = source.getOutputAnchorPoint(connection.getOutput());
        if (sourcePoint == null) {
            return false;
        }

        Point targetPoint = target.getInputAnchorPoint(connection.getInput());
        if (targetPoint == null) {
            return false;
        }

        return createRectangle(sourcePoint, targetPoint).intersects(
                new Rectangle(0, 0, viewportSize.width, viewportSize.height));
    }

    /**
     * Creates a rectangle from the given two points, ordering them as necessary.
     * @param a First point
     * @param b Second point
     * @return Rectangle created from the given input points.
     */
    private Rectangle createRectangle(Point a, Point b) {
        int min_x = Math.min(a.x, b.x);
        int min_y = Math.min(a.y, b.y);
        int max_x = Math.max(a.x, b.x);
        int max_y = Math.max(a.y, b.y);
        int width = max_x - min_x;
        int height = max_y - min_y;
        return new Rectangle(min_x, min_y, width, height);
    }

    public java.util.List<NodeConnection> getVisibleConnections() {
        return visibleConnections;
    }

    public java.util.List<NodeConnection> getConnections() {
        return page.getProject().getNodeConnections().stream()
                .filter(connection -> connection.getSource().getModule() == module
                        || connection.getTarget().getModule() == module)
                .toList();
    }

    public java.util.List<NodeConnection> getConnections(GraphNode node) {
        return getConnections().stream().filter(
                connection -> connection.getSource() == node
        ).collect(Collectors.toList());
    }

    private void paintGridlines(Graphics2D g2d) {
        g2d.setColor(getBackground().brighter());
        Path2D.Float minorGridLines = new Path2D.Float();
        for (int x = 0; x < getWidth(); x += gridSize / gridCells) {
            minorGridLines.moveTo(x, 0);
            minorGridLines.lineTo(x, getHeight());
        }
        for (int y = 0; y < getHeight(); y += gridSize / gridCells) {
            minorGridLines.moveTo(0, y);
            minorGridLines.lineTo(getWidth(), y);
        }
        g2d.draw(minorGridLines);

        g2d.setColor(getBackground().darker());
        Path2D.Float majorGridLines = new Path2D.Float();
        for (int x = 0; x < getWidth(); x += gridSize) {
            majorGridLines.moveTo(x, 0);
            majorGridLines.lineTo(x, getHeight());
        }
        for (int y = 0; y < getHeight(); y += gridSize) {
            majorGridLines.moveTo(0, y);
            majorGridLines.lineTo(getWidth(), y);
        }
        g2d.draw(majorGridLines);
    }

    @Override
    public void paint(Graphics g) {
        Graphics2D g2d = (Graphics2D) g;
        g.setColor(getBackground());
        g.fillRect(0, 0, getWidth(), getHeight());

        if (Settings.GRAPH_EDITOR_DRAW_GRID_LINES.get()) {
            paintGridlines(g2d);
        }

        super.paint(g);

        g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

        java.util.List<NodeConnection> connections = getVisibleConnections();
        java.util.List<NodeConnection> hoveredConnections = new ArrayList<>();
        for (NodeConnection connection : connections) {
            boolean isHoveredEndpoint = hoveredEndpoint != null &&
                    ((connection.getSource() == hoveredEndpoint.getGraphNode()
                            && connection.getOutput() == hoveredEndpoint.getEndpoint()) ||
                    (connection.getTarget() == hoveredEndpoint.getGraphNode()
                            && connection.getInput() == hoveredEndpoint.getEndpoint()));

            if (pressedEndpoint != null || hoveredConnection != connection && !isHoveredEndpoint) {
                paintConnection(g2d, connection, false);
            } else {
                // Queue to render later (on top)
                hoveredConnections.add(connection);
            }
        }

        // The currently hovered connections will always show on 'top'
        for (NodeConnection hoveredConnection : hoveredConnections) {
            paintConnection(g2d, hoveredConnection, true);
        }

        // Paint the connection being created
        if (pressedEndpoint != null) {
            NodeComponent component = nodes.get(pressedEndpoint.getGraphNode());
            if (component != null) {
                Point source = screenToRelative(pressedEndpoint.getAnchorPoint());

                Point target;
                if (hoveredEndpoint != null) {
                    target = screenToRelative(hoveredEndpoint.getAnchorPoint());
                } else {
                    target = getMousePosition();
                }

                Color color = new Color(0x707070);

                if (pressedEndpoint.getEndpoint() instanceof NodeInput<?>) {
                    // Flip the endpoints for the Bézier curve order
                    Point temp = source;
                    source = target;
                    target = temp;
                } else if (pressedEndpoint.getEndpoint() instanceof NodeOutput<?> output) {
                   color = output.getColorUnchecked(pressedEndpoint.getGraphNode());
                }

                paintConnection(g2d, source, target, color, true);
            }
        }
    }

    @Override
    public void close() {

    }

    private void updateBounds() {
        Dimension currentSize = getVisibleRect().getSize();
        Rectangle rectangle = new Rectangle(0, 0, currentSize.width, currentSize.height);

        for (Component component : getComponents()) {
            rectangle.x = Math.min(rectangle.x, component.getX());
            rectangle.y = Math.min(rectangle.y, component.getY());
        }

        if (rectangle.x < 0 || rectangle.y < 0) {
            for (Component component : getComponents()) {
                Point location = component.getLocation();
                location = new Point(location.x - rectangle.x, location.y - rectangle.y);
                component.setLocation(location);
            }
        }

        for (Component component : getComponents()) {
            rectangle.width = Math.max(rectangle.width, component.getX() + component.getWidth());
            rectangle.height = Math.max(rectangle.height, component.getY() + component.getHeight());
        }

        rectangle.width += emptyBufferSpace;
        rectangle.height += emptyBufferSpace;

        Dimension newSize = rectangle.getSize();
        setSize(newSize);
        setPreferredSize(newSize);
    }

    @Override
    public void componentResized(ComponentEvent e) {
        updateBounds();
        updateVisibleNodes();
        repaint();
    }

    @Override
    public void componentMoved(ComponentEvent e) {
        updateBounds();
        updateVisibleNodes();
        repaint();
    }

    @Override
    public void componentShown(ComponentEvent e) {
        updateBounds();
        updateVisibleNodes();
        repaint();
    }

    @Override
    public void componentHidden(ComponentEvent e) {
        updateBounds();
        updateVisibleNodes();
        repaint();
    }

    public void onNodeChanged() {
        page.getEditor().fireModelChange(Model.GRAPH, ChangeType.MODIFIED);
        updateVisibleNodes();
    }

    @Override
    public void onMemoryFrame(MemoryFrame frame) {
        boolean changed = false;
        for (NodeComponent component : getNodeComponents()) {
            if (component.getGraphNode() instanceof ParameterNode node) {
                changed = changed | component.setValue(frame.getValue(node.getParameter()));
            }
        }

        if (changed) {
            SwingUtilities.invokeLater(this::repaint);
        }
    }
}
