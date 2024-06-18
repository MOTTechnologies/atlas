package com.github.manevolent.atlas.ui.component.graph;

import com.github.manevolent.atlas.model.MemoryParameter;
import com.github.manevolent.atlas.model.node.*;
import com.github.manevolent.atlas.settings.Settings;
import com.github.manevolent.atlas.ui.Editor;
import com.github.manevolent.atlas.ui.behavior.Animation;
import com.github.manevolent.atlas.ui.behavior.ChangeType;
import com.github.manevolent.atlas.ui.behavior.Model;
import com.github.manevolent.atlas.ui.behavior.TimedAnimation;
import com.github.manevolent.atlas.ui.component.popupmenu.graph.NodePopupMenu;

import com.github.manevolent.atlas.ui.util.Colors;
import com.github.manevolent.atlas.ui.util.Fonts;
import com.github.manevolent.atlas.ui.util.Labels;

import javax.swing.*;
import java.awt.*;

import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.geom.Path2D;
import java.awt.geom.Rectangle2D;
import java.nio.file.Path;
import java.util.*;
import java.util.List;

/**
 * You can think of this as a view for a GraphNode. A NodeComponent is the Swing component that represents the
 * view + controller logic for the GraphNode Model object.
 */
public class DefaultNodeComponent extends JPanel implements NodeComponent {
    private static final int textPadding = 3;
    private static final Color textBackgroundColor = Colors.withAlpha(Color.BLACK, 180);

    private static final Color highlightColor = new Color(0xc0a930);
    private static final Color borderColor = new Color(0x505050);
    private static final Color backgroundColor = new Color(0x202020);
    private static final Color headerColor = new Color(0x304C79);
    private static final Color textColor = Color.WHITE;

    /**
     * The GraphNode model this component renders/controls for.
     */
    private final GraphNode graphNode;

    private final DefaultGraphRenderer renderer;

    private final Map<NodeInput<?>, DefaultEndpointComponent> inputNodes = new LinkedHashMap<>();
    private final Map<NodeOutput<?>, DefaultEndpointComponent> outputNodes = new LinkedHashMap<>();
    private final Map<NodeConnection, DefaultConnectionComponent> connections = new LinkedHashMap<>();

    private JPanel inputContent, outputContent;
    private Point lastLocation;
    private Point lastDragLocation;

    private Animation highlight;
    private double highlightLevel = 0D;

    private Float lastValue;

    public DefaultNodeComponent(GraphNode graphNode, DefaultGraphRenderer renderer) {
        this.graphNode = graphNode;
        this.renderer = renderer;

        initComponent();
    }

    public Editor getEditor() {
        return renderer.getPage().getEditor();
    }

    private void initComponent() {
        setBorder(BorderFactory.createMatteBorder(1, 1, 1, 1, borderColor));

        setLayout(new BorderLayout());

        JLabel title = Labels.text(graphNode.getIcon(), textColor, graphNode.getLabel(), textColor);
        title.setCursor(Cursor.getPredefinedCursor(Cursor.MOVE_CURSOR));

        Color preferredColor = graphNode.getLabelColor();
        title.setBackground(preferredColor != null ? preferredColor.darker() : headerColor);
        title.setOpaque(true);
        title.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));
        title.setComponentPopupMenu(new NodePopupMenu(DefaultNodeComponent.this).getComponent());
        title.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                titlePressed(e);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                titleReleased(e);
            }

            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() > 1 && e.getButton() == MouseEvent.BUTTON1) {
                    titleDoubleClicked(e);
                }
            }
        });
        title.addMouseMotionListener(new MouseAdapter() {
            @Override
            public void mouseDragged(MouseEvent e) {
                titleDragged(e);
            }
        });
        add(title, BorderLayout.NORTH);

        JPanel content = new JPanel(new BorderLayout()) {
            @Override
            public void paint(Graphics g) {
                super.paint(g);
                paintOverlay(g, this);
            }
        };
        content.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));
        content.setOpaque(true);
        content.setBackground(backgroundColor);

        JComponent settingComponent = graphNode.getSettingComponent();

        inputContent = new JPanel();
        inputContent.setLayout(new BoxLayout(inputContent, BoxLayout.Y_AXIS));
        inputContent.setBackground(backgroundColor);
        content.add(inputContent, BorderLayout.WEST);

        outputContent = new JPanel();
        outputContent.setLayout(new BoxLayout(outputContent, BoxLayout.Y_AXIS));
        outputContent.setBackground(backgroundColor);
        content.add(outputContent, BorderLayout.EAST);

        if (settingComponent != null) {
            JScrollPane scrollPane = new JScrollPane(settingComponent);
            scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
            scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
            scrollPane.setBorder(BorderFactory.createEmptyBorder());
            scrollPane.setPreferredSize(new Dimension(256, 100));
            scrollPane.setMinimumSize(new Dimension(256, 100));
            scrollPane.setMaximumSize(new Dimension(256, 100));

            add(scrollPane, BorderLayout.CENTER);
            add(content, BorderLayout.SOUTH);
        } else {
            add(content, BorderLayout.CENTER);
        }

        setLocation((int)graphNode.getX(), (int)graphNode.getY());
    }

    public void paintOverlay(Graphics g, JComponent panel) {
        if (lastValue != null && graphNode instanceof ParameterNode parameterNode) {
            MemoryParameter parameter = parameterNode.getParameter();
            String text = parameter.getScale().formatPreferred(lastValue);

            Graphics2D g2d = (Graphics2D) g;
            g2d.setFont(Fonts.VALUE_FONT);
            FontMetrics metrics = g2d.getFontMetrics();
            Rectangle2D bounds = metrics.getStringBounds(text, g2d);

            int x = (panel.getWidth() / 2) - (int) (bounds.getWidth() / 2);
            int y = (panel.getHeight() / 2) - (int) (bounds.getHeight() / 2);
            Rectangle2D rectangle2D = new Rectangle2D.Float(
                    x - textPadding,
                    y + metrics.getMaxDescent() - textPadding,
                    (float) bounds.getWidth() + (textPadding * 2),
                    (float) bounds.getHeight() + (textPadding * 2));

            g2d.setColor(textBackgroundColor);
            g2d.fill(rectangle2D);

            g2d.setColor(Color.WHITE);
            g2d.drawString(text, x, (int) (y + bounds.getHeight()));
        }
    }

    public void reload() {
        connections.clear();
        inputNodes.clear();
        outputNodes.clear();

        removeAll();

        initComponent();
        revalidate();

        setupEndpoints();
        setupConnections();
    }

    public void setLocation(int x, int y) {
        graphNode.setX(x);
        graphNode.setY(y);

        super.setLocation(x, y);
    }

    private void titleDoubleClicked(MouseEvent e) {
        if (graphNode instanceof TableNode tableNode) {
            getEditor().openTable(tableNode.getTable());
        } else if (graphNode instanceof ParameterNode parameterNode) {
            getEditor().openParameter(parameterNode.getParameter());
        }
    }

    private void titlePressed(MouseEvent e) {
        if (e.getButton() == MouseEvent.BUTTON1) {
            if (graphNode instanceof TableNode tableNode) {
                getEditor().getProjectTreeTab().onItemOpened(tableNode.getTable());
            } else if (graphNode instanceof ParameterNode parameterNode) {
                getEditor().getProjectTreeTab().onItemOpened(parameterNode.getParameter());
            }
        }

        lastLocation = getLocation();
        lastDragLocation = e.getLocationOnScreen();
    }

    private Point snapPoint(Point point) {
        if (Settings.GRAPH_EDITOR_DRAW_GRID_LINES.get()) {
            float x = point.x;
            float y = point.y;

            float grid_size = (float) DefaultGraphRenderer.gridSize / DefaultGraphRenderer.gridCells;
            int grid_x = (int) Math.floor(x / grid_size);
            int grid_y = (int) Math.floor(y / grid_size);

            return new Point((int) Math.floor(grid_x * grid_size), (int) Math.floor(grid_y * grid_size));
        } else {
            // No snap
            return point;
        }
    }

    private void titleDragged(MouseEvent e) {
        if (lastDragLocation != null && lastLocation != null) {
            int d_x = lastLocation.x + (e.getLocationOnScreen().x - lastDragLocation.x);
            int d_y = lastLocation.y + (e.getLocationOnScreen().y - lastDragLocation.y);
            Point newLocation = new Point(d_x, d_y);
            newLocation = snapPoint(newLocation);
            setLocation(newLocation);
        }
    }

    private void titleReleased(MouseEvent e) {
        boolean changed = false;

        if (graphNode.getX() != getX()) {
            graphNode.setX(getX());
            changed = true;
        }

        if (graphNode.getY() != getY()) {
            graphNode.setY(getY());
            changed = true;
        }

        if (changed) {
            renderer.onNodeChanged();
        }

        lastDragLocation = null;
        lastLocation = null;
    }

    public String getTitle() {
        return graphNode.getLabel();
    }

    @Override
    public GraphNode getGraphNode() {
        return graphNode;
    }

    @Override
    public void doLayout() {
        super.doLayout();
        setSize(getPreferredSize());
    }

    private DefaultEndpointComponent createEndpoint(NodeEndpoint<?> endpoint, int orientation) {
        return new DefaultEndpointComponent(graphNode, endpoint, orientation, renderer);
    }

    private DefaultConnectionComponent createConnection(NodeConnection connection) {
        return new DefaultConnectionComponent(connection);
    }

    @Override
    public List<EndpointComponent> setupEndpoints() {
        List<EndpointComponent> endpoints = new ArrayList<>();

        graphNode.getInputs().forEach(node -> {
            DefaultEndpointComponent endpoint = createEndpoint(node, SwingConstants.LEFT);
            endpoint.setAlignmentX(0f);
            inputContent.add(endpoint);
            inputContent.add(Box.createVerticalGlue());
            endpoints.add(endpoint);
            inputNodes.put(node, endpoint);
        });

        graphNode.getOutputs().forEach(node -> {
            DefaultEndpointComponent endpoint = createEndpoint(node, SwingConstants.RIGHT);
            endpoint.setAlignmentX(1f);
            outputContent.add(Box.createVerticalGlue());
            outputContent.add(endpoint);
            outputContent.add(Box.createVerticalGlue());
            endpoints.add(endpoint);
            outputNodes.put(node, endpoint);
        });

        doLayout();

        return endpoints;
    }

    @Override
    public List<ConnectionComponent> setupConnections() {
        List<ConnectionComponent> connections = new ArrayList<>();

        renderer.getConnections(graphNode).forEach(conn -> {
            DefaultConnectionComponent connection = createConnection(conn);
            DefaultNodeComponent.this.connections.put(conn, connection);
        });

        return connections;
    }

    public DefaultEndpointComponent getEndpointComponent(NodeEndpoint<?> endpoint) {
        DefaultEndpointComponent endpointComponent = outputNodes.get(endpoint);
        if (endpointComponent != null) {
            return endpointComponent;
        }

        endpointComponent = inputNodes.get(endpoint);
        return endpointComponent;
    }

    @Override
    public Point getAnchorPoint(NodeEndpoint<?> endpoint) {
        if (endpoint instanceof NodeOutput<?> output) {
            return getOutputAnchorPoint(output);
        } else if (endpoint instanceof NodeInput<?> input) {
            return getInputAnchorPoint(input);
        } else {
            throw new UnsupportedOperationException(endpoint.getClass().getName());
        }
    }

    @Override
    public Point getOutputAnchorPoint(NodeOutput<?> endpoint) {
        DefaultEndpointComponent endpointComponent = outputNodes.get(endpoint);
        if (endpointComponent == null) {
            return null;
        }
        return endpointComponent.getAnchorPoint();
    }

    @Override
    public Point getInputAnchorPoint(NodeInput<?> endpoint) {
        DefaultEndpointComponent endpointComponent = inputNodes.get(endpoint);
        if (endpointComponent == null) {
            return null;
        }
        return endpointComponent.getAnchorPoint();
    }

    @Override
    public void highlight() {
        if (highlight != null) {
            highlight.interrupt();
            highlight = null;
        }

        highlight = new TimedAnimation(renderer, 0.8D) {
            @Override
            protected void update(double position, JComponent component) {
                highlightLevel = 1D - (Math.pow(position, 1.2D));
            }
        };

        highlight.start();
    }

    @Override
    public boolean setValue(Float value) {
        if (!Objects.equals(this.lastValue, value)) {
            this.lastValue = value;
            return true;
        } else {
            return false;
        }
    }

    @Override
    public Float getValue() {
        return lastValue;
    }

    @Override
    public boolean isShowingOnScreen() {
        if (!isShowing()) {
            return false;
        }

        Rectangle visibleRectangle = getVisibleRect();
        return visibleRectangle.getWidth() * visibleRectangle.getHeight() > 0;
    }

    @Override
    public void paint(Graphics g) {
        super.paint(g);

        if (highlightLevel > 0D) {
            g.setColor(Colors.withAlpha(highlightColor, (int) ((highlightLevel * 0.8D) * 255D)));
            g.fillRect(0, 0, getWidth(), getHeight());
        }
    }

    public void delete() {
        if (JOptionPane.showConfirmDialog(getEditor(),
                "Are you sure you want to delete " + getGraphNode().getLabel() + "?",
                "Delete Node",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE) != JOptionPane.YES_OPTION) {
            return;
        }

        renderer.deleteComponent(this);
        Editor editor = getEditor();
        editor.getProject().removeGraphNode(graphNode);
        editor.fireModelChange(Model.GRAPH, ChangeType.MODIFIED);
    }

    @Override
    public boolean isVisible() {
        return super.isVisible();
    }
}
