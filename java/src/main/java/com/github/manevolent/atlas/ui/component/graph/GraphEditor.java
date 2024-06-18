package com.github.manevolent.atlas.ui.component.graph;

import com.github.manevolent.atlas.connection.MemoryFrame;
import com.github.manevolent.atlas.model.MemoryParameter;
import com.github.manevolent.atlas.model.Project;
import com.github.manevolent.atlas.model.Table;
import com.github.manevolent.atlas.model.node.*;
import com.github.manevolent.atlas.settings.Settings;
import com.github.manevolent.atlas.ui.Editor;
import com.github.manevolent.atlas.ui.behavior.*;
import com.github.manevolent.atlas.ui.component.Window;
import com.github.manevolent.atlas.ui.component.popupmenu.graph.GraphPopupMenu;
import com.github.manevolent.atlas.ui.component.tab.TreeTab;
import com.github.manevolent.atlas.ui.util.Icons;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.event.AdjustmentEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static com.github.manevolent.atlas.ui.util.Inputs.showOptionDialog;

public class GraphEditor extends Window implements ModelChangeListener, MemoryFrameListener, LiveWindow {
    private final GraphModule module;

    private GraphComponent view;
    private GraphRenderer renderer;
    private Point lastMouseLocation;
    private JScrollPane scrollPane;

    public GraphEditor(Editor editor, GraphModule module) {
        super(editor);
        this.module = module;
    }

    public GraphModule getGraph() {
        return module;
    }

    @Override
    public String getTitle() {
        return "Graph Editor - " + module.getName();
    }

    @Override
    public Icon getIcon() {
        return Icons.get(CarbonIcons.DATA_VIS_3);
    }

    @Override
    public void reload() {
        //TODO
    }

    public Editor getEditor() {
        return getParent();
    }

    public Project getProject() {
        return getEditor().getProject();
    }

    public GraphModule getModule() {
        return module;
    }

    @Override
    protected void initComponent(JInternalFrame frame) {
        frame.setLayout(new BorderLayout());

        // Make sure the renderer is instantiated and set up appropriately
        if (renderer == null) {
            renderer = new DefaultGraphRenderer(this, module);
        }

        createGraph();

        view = initGraphView();
        view.setComponentPopupMenu(new GraphPopupMenu(this).getComponent());
        view.addMouseMotionListener(new MouseAdapter() {
            @Override
            public void mouseMoved(MouseEvent e) {
                lastMouseLocation = e.getPoint();
            }
        });
        view.setTransferHandler(new TransferHandler());

        scrollPane = new JScrollPane(view);
        scrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setBorder(BorderFactory.createEmptyBorder());

        scrollPane.getHorizontalScrollBar().addAdjustmentListener((e) -> onScrollAdjusted(e));
        scrollPane.getVerticalScrollBar().addAdjustmentListener((e) -> onScrollAdjusted(e));
        frame.add(scrollPane, BorderLayout.CENTER);
    }

    private void onScrollAdjusted(AdjustmentEvent e) {
        view.updateVisibleNodes();

        if (!e.getValueIsAdjusting() && Settings.GRAPH_EDITOR_LIVE.get()) {
            getEditor().updateParameters();
        }
    }

    @Override
    public Set<MemoryParameter> getParameters() {
        return renderer.getVisibleComponents()
                .filter(c -> c.getGraphNode() instanceof ParameterNode)
                .map(c -> (ParameterNode) c.getGraphNode())
                .map(ParameterNode::getParameter)
                .collect(Collectors.toSet());
    }

    @Override
    public boolean isLive() {
        return Settings.GRAPH_EDITOR_LIVE.get();
    }

    /**
     * Reloads the current graph
     */
    public void reloadGraph() {
        renderer.reset();
        createGraph();
    }

    /**
     * Loads a graph from the project model.
     */
    public java.util.List<NodeComponent> createGraph() {
        // Get all the graph nodes
        java.util.List<GraphNode> nodes = getProject().getGraphNodes(module);

        // Render all nodes to components
        java.util.List<NodeComponent> components = nodes.stream().map(renderer::createComponent).toList();

        // Setup every component's nodes (I/O) and edges (connections between I/O nodes)
        components.forEach(NodeComponent::setupEndpoints); // Nodes are the I/O on the sides of the components
        components.forEach(NodeComponent::setupConnections); // Edges happen last, as referencing might need to happen

        return components;
    }

    public void addConnection(NodeConnection connection) {
        if (!getProject().hasNodeConnection(connection)) {
            getProject().addNodeConnection(connection);
            getEditor().fireModelChange(Model.GRAPH, ChangeType.MODIFIED);
        }
    }

    public void removeConnection(NodeConnection connection) {
        getProject().removeNodeConnection(connection);
        getEditor().fireModelChange(Model.GRAPH, ChangeType.MODIFIED);
    }

    public void newDocumentationNode() {
        Point nodeLocation = this.lastMouseLocation;

        // Fallback; this shouldn't happen, though.
        if (nodeLocation == null) {
            nodeLocation = new Point(0, 0);
        }

        DocumentationNode newNode = new DocumentationNode();
        newNode.setModule(module);
        newNode.setX(nodeLocation.x);
        newNode.setY(nodeLocation.y);

        getProject().addGraphNode(newNode);

        NodeComponent component = renderer.createComponent(newNode);
        component.setupEndpoints();
        component.setupConnections();

        getEditor().fireModelChange(Model.GRAPH, ChangeType.MODIFIED);
    }

    private List<Table> getAvailableTables() {
        return getProject().getTables().stream()
                .filter(t -> getProject().getGraphNodes().stream().noneMatch(
                        node -> node instanceof TableNode tableNode && tableNode.getTable() == t)
                ).toList();
    }

    public void addNode(GraphNode node) {
        getProject().addGraphNode(node);

        NodeComponent component = renderer.createComponent(node);
        component.setupEndpoints();
        component.setupConnections();

        getEditor().fireModelChange(Model.GRAPH, ChangeType.MODIFIED);
    }

    public void newTableNode() {
        Point nodeLocation = this.lastMouseLocation;

        // Fallback; this shouldn't happen, though.
        if (nodeLocation == null) {
            nodeLocation = new Point(0, 0);
        }

        java.util.List<Table> options = getAvailableTables();

        Table table = showOptionDialog(getEditor(), "Add Table Node", "Select a Table:", options);
        if (table == null) {
            return;
        }

        addTable(table, nodeLocation);
    }

    public void addTable(Table table, Point point) {
        TableNode newNode = new TableNode();
        newNode.setModule(module);
        newNode.setTable(table);
        newNode.setX(point.x);
        newNode.setY(point.y);

        addNode(newNode);
    }

    public void newParameterNode() {
        Point nodeLocation = this.lastMouseLocation;

        // Fallback; this shouldn't happen, though.
        if (nodeLocation == null) {
            nodeLocation = new Point(0, 0);
        }

        List<MemoryParameter> options = getProject().getParameters().stream().toList();
        MemoryParameter parameter = showOptionDialog(getEditor(), "Add Parameter Node", "Select a Parameter:", options);
        if (parameter == null) {
            return;
        }

        addParameter(parameter, nodeLocation);
    }

    public void addParameter(MemoryParameter parameter, Point point) {
        ParameterNode newNode = new ParameterNode();
        newNode.setModule(module);
        newNode.setParameter(parameter);
        newNode.setX(point.x);
        newNode.setY(point.y);

        addNode(newNode);
    }

    /**
     * Initializes the node graph as a render-able (paint-able) JComponent. The JComponent should already be plugged
     * with the event listeners needed to manipulate existing nodes, but there will still be a need for this GraphWindow
     * to attach its own popup listeners, etc. for the sake of the UI.
     * @return JComponent instance used to render the graph to a surface.
     */
    private GraphComponent initGraphView() {
        return renderer.createRenderTarget();
    }

    @Override
    public void onModelChanged(Model model, ChangeType changeType) {
        if (model == Model.TABLE || model == Model.PARAMETER || model == Model.GRAPH) {
            view.repaint();
        }
    }

    public boolean close() {
        renderer.close();
        return true;
    }

    public void findNode(GraphNode node) {
        SwingUtilities.invokeLater(() -> {
            NodeComponent component = renderer.getComponent(node);
            if (component == null) {
                return;
            }

            if (component instanceof JComponent jComponent) {
                Rectangle rectangle = new Rectangle(jComponent.getVisibleRect());
                rectangle.translate(
                        - ((scrollPane.getWidth() / 2) - (jComponent.getWidth() / 2)),
                        - ((scrollPane.getHeight() / 2) - (jComponent.getHeight() / 2)));
                rectangle.setSize(scrollPane.getSize());
                jComponent.scrollRectToVisible(rectangle);
            }

            component.highlight();

            getEditor().updateParameters();
        });
    }

    @Override
    public void onMemoryFrame(MemoryFrame frame) {
        if (renderer != null) {
            renderer.onMemoryFrame(frame);
        }
    }

    private class TransferHandler extends javax.swing.TransferHandler {
        @Override
        public boolean canImport(TransferSupport support) {
            TreeTab.Item item = getItem(support);
            return item != null;
        }

        private TreeTab.Item getItem(TransferSupport support) {
            Object object;
            try {
                object = support.getTransferable().getTransferData(TreeTab.ITEM_DATA_FLAVOR);
            } catch (UnsupportedFlavorException | IOException e) {
                return null;
            }

            TreeTab.Item item = (TreeTab.Item) object;
            if (item instanceof Table table) {
                if (!getAvailableTables().contains(table)) {
                    return null;
                }
            }

            return item;
        }

        @Override
        public boolean importData(TransferSupport support) {
            TreeTab.Item item = getItem(support);
            if (item == null) {
                return false;
            }

            Point dropPoint = support.getDropLocation().getDropPoint();
            if (item instanceof Table table) {
                addTable(table, dropPoint);
            } else if (item instanceof MemoryParameter parameter) {
                addParameter(parameter, dropPoint);
            } else {
                return false;
            }

            return true;
        }
    }
}
