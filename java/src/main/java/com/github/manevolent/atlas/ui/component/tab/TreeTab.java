package com.github.manevolent.atlas.ui.component.tab;

import com.github.manevolent.atlas.logging.Log;
import com.github.manevolent.atlas.model.Calibration;
import com.github.manevolent.atlas.model.Variant;
import com.github.manevolent.atlas.settings.Settings;
import com.github.manevolent.atlas.ui.Editor;

import com.github.manevolent.atlas.ui.util.Fonts;
import com.github.manevolent.atlas.ui.util.Icons;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.kordamp.ikonli.Ikon;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.tree.*;
import java.awt.*;

import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.datatransfer.UnsupportedFlavorException;

import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.awt.image.BufferedImage;
import java.util.*;
import java.util.List;

import java.util.logging.Level;

public abstract class TreeTab extends Tab implements TreeSelectionListener, MouseListener {
    public static DataFlavor ITEM_DATA_FLAVOR = new DataFlavor(Item.class, "Tree Item");

    private static final Comparator<Item> depthComparator = Comparator.comparing(
            item -> item.getTreeName().split(" - ").length);

    private static final Comparator<Item> nameComparator = Comparator.comparing(Item::getTreeName);

    private static final Comparator<Item> ordinalComparator = Comparator.comparing(Item::getTreeOrdinal);

    /**
     * Primary comparator for the UI element
     */
    private static final Comparator<Item> comparator =
            depthComparator.reversed()
            .thenComparing(ordinalComparator)
            .thenComparing(nameComparator);

    private JTree tree;
    private JTextField searchField;
    private Map<TreeTab.Item, LeafNode<TreeTab.Item>> nodeMap = new HashMap<>();
    private List<TreeTab.Item> lastExpansions = new ArrayList<>();
    private DefaultTreeModel defaultModel;

    protected TreeTab(Editor editor, JTabbedPane pane) {
        super(editor, pane);
    }

    public abstract Collection<TreeTab.Item> getItems();

    protected abstract void openItem(TreeTab.Item item);

    protected abstract JPopupMenu getPopupMenu(TreeNode node);

    @Override
    protected void initComponent(JPanel panel) {
        panel.setLayout(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0));

        // Search
        searchField = new JTextField();
        searchField.setToolTipText("Search items");

        searchField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                search(searchField.getText());
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                search(searchField.getText());
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                search(searchField.getText());
            }
        });

        panel.add(searchField, BorderLayout.SOUTH);

        // Tree
        tree = new JTree();
        tree.addTreeSelectionListener(this);
        tree.addMouseListener(this);
        tree.setCellRenderer(new Renderer(getEditor()));
        tree.setDragEnabled(true);
        tree.setTransferHandler(new TransferHandler());

        // You can only be focused on one table at a time
        tree.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);

        nodeMap.clear();

        tree.setModel(defaultModel = new DefaultTreeModel(buildModel(null)));
        tree.setBackground(new Color(0, 0, 0, 0));
        tree.setBorder(BorderFactory.createEmptyBorder(0, 5, 0, 0));
        tree.addTreeExpansionListener(new TreeExpansionListener() {
            @Override
            public void treeExpanded(TreeExpansionEvent event) {
                TreePath selection = tree.getSelectionPath();

                // Collapse everything under a given node when its parent is collapsed
                getPathsUnder(event.getPath()).stream()
                        .filter(path -> tree.isExpanded(path))
                        .filter(path -> selection == null || !path.isDescendant(selection))
                        .forEach(path -> tree.collapsePath(path));

                if (selection != null) {
                    tree.setSelectionPath(selection);
                }

                updateExpansions();
            }

            @Override
            public void treeCollapsed(TreeExpansionEvent event) {
                // Don't allow collapsing the root node
                if (event.getPath().getLastPathComponent() == tree.getModel().getRoot()) {
                    tree.expandPath(event.getPath());
                    return;
                }

                updateExpansions();
            }
        });

        JPanel treePanel = new JPanel();

        treePanel.setLayout(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.anchor = GridBagConstraints.NORTHWEST;
        c.gridx = 0;
        c.gridy = 0;
        c.weightx = 1;
        c.weighty = 1;
        c.gridwidth = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        treePanel.add(tree, c);

        JScrollPane scrollPane = new JScrollPane(
                treePanel,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        scrollPane.getVerticalScrollBar().addAdjustmentListener(e -> {
            scrollPane.revalidate();
            scrollPane.repaint();
        });

        scrollPane.getHorizontalScrollBar().addAdjustmentListener(e -> {
            scrollPane.revalidate();
            scrollPane.repaint();
        });

        scrollPane.setViewportBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0));
        scrollPane.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0));

        panel.add(scrollPane, BorderLayout.CENTER);
    }

    public void onItemOpened(TreeTab.Item item) {
        if (!Settings.AUTO_SELECT_ITEM.get()) {
            return;
        }

        LeafNode<TreeTab.Item> node = nodeMap.get(item);
        if (node == null) {
            return;
        }

        TreePath path = getPath(item);
        tree.getSelectionModel().setSelectionPath(path);
        tree.makeVisible(path);
        tree.scrollPathToVisible(path);

        // Bugfix for UI elements that seemingly repaint in a strange way
        this.getComponent().repaint();
    }

    @Override
    public void valueChanged(TreeSelectionEvent e) {
        TreePath selPath = e.getPath();
        Object last = selPath != null ? selPath.getLastPathComponent() : null;

        // Don't allow the root note to be selected
        if (last == tree.getModel().getRoot()) {
            tree.setSelectionRows(new int[0]);
            return;
        }

        tree.setComponentPopupMenu(getPopupMenu((TreeNode) last));
    }

    public void update() {
        List<TreeTab.Item> expansions = getExpansions();
        tree.setModel(defaultModel = new DefaultTreeModel(buildModel(null)));
        expand(expansions);

        getComponent().revalidate();
        getComponent().repaint();
    }

    public void open(TreePath selPath) {
        if (selPath == null) {
            return;
        }

        Object last = selPath.getLastPathComponent();
        if (last instanceof TreeTab.LeafNode<?> leafNode) {
            openItem(leafNode.getItem());
        }
    }

    private void reexpand() {
        expand(lastExpansions);
    }

    private void expand(List<TreeTab.Item> expansions) {
        Log.ui().log(Level.FINER, "Re-expanding items (" + lastExpansions.size() + " expansions)");

        for (TreeTab.Item item : expansions) {
            TreePath path = getPath(item);
            if (path == null) {
                continue;
            }

            Log.ui().log(Level.FINER, "Re-expanding " + Arrays.toString(path.getPath()));
            path = path.getParentPath();
            tree.expandPath(path);
            tree.makeVisible(path);
        }

        getComponent().revalidate();
        getComponent().repaint();
    }

    private void updateExpansions() {
        if (!searchField.getText().isEmpty()) {
            return;
        }

        lastExpansions = getExpansions();
    }

    private List<TreeTab.Item> getExpansions() {
        //noinspection unchecked
        return Collections.list((tree.getExpandedDescendants(new TreePath(tree.getModel().getRoot()))))
                .stream()
                .map(TreePath::getLastPathComponent)
                .filter(c -> c instanceof DefaultMutableTreeNode)
                .map(c -> (DefaultMutableTreeNode) c)
                .flatMap(n -> Collections.list(n.children()).stream())
                .filter(c -> c instanceof TreeTab.LeafNode<?>)
                .map(c -> (LeafNode<TreeTab.Item>) c)
                .map(LeafNode::getItem)
                .toList();
    }

    /**
     * Gets the JTree instance backing this TreeTab.
     * @return JTree instance.
     */
    public JTree getTree() {
        return tree;
    }

    /**
     * Gets an item for a specific tree node
     * @param node node to convert to a tree item
     * @return instance of T if the node represents a leaf for a specific item, or null otherwise.
     */
    public TreeTab.Item getItem(TreeNode node) {
        if (node instanceof TreeTab.LeafNode) {
            //noinspection unchecked
            return ((TreeTab.LeafNode<TreeTab.Item>) node).getItem();
        }

        return null;
    }

    public TreePath getPath(TreeNode node) {
        if (node == null) {
            throw new NullPointerException("node");
        } else if (node instanceof TreeTab.LeafNode<?> leafNode) {
            return getPath(leafNode.getItem());
        } else {
            DefaultTreeModel model = (DefaultTreeModel) tree.getModel();
            TreeNode[] nodes = model.getPathToRoot(node);
            return new TreePath(nodes);
        }
    }

    public TreePath getPath(TreeTab.Item leaf) {
        TreeTab.LeafNode<TreeTab.Item> node = nodeMap.get(leaf);
        if (node == null) {
            return null;
        }

        DefaultTreeModel model = (DefaultTreeModel) tree.getModel();
        TreeNode[] nodes = model.getPathToRoot(node);
        return new TreePath(nodes);
    }

    private DefaultMutableTreeNode buildModel(String search) {
        DefaultMutableTreeNode treeRoot = new DefaultMutableTreeNode();
        List<TreeTab.Item> sortedItems = getItems().stream().sorted(comparator).toList();

        for (TreeTab.Item item : sortedItems) {
            if (search != null && !item.getTreeName().toLowerCase().contains(search.toLowerCase())) {
                continue;
            }

            List<String> nodes = Arrays.stream(item.getTreeName().split(" - ")).map(String::trim).toList();
            MutableTreeNode parent = treeRoot;
            for (int i = 0 ; i < nodes.size(); i ++) {
                String text = nodes.get(i);

                // Find an existing child, if possible
                MutableTreeNode child = Collections.list(Objects.requireNonNull(parent.children()))
                        .stream()
                        .filter(x -> x instanceof DefaultMutableTreeNode)
                        .map(x -> (DefaultMutableTreeNode)x)
                        .filter(x -> x.getUserObject().toString().equals(text))
                        .findFirst()
                        .orElse(null);

                if (child == null) {
                    boolean isLeaf = i == nodes.size() - 1;
                    if (isLeaf) {
                        LeafNode<TreeTab.Item> tableNode = new TreeTab.LeafNode<>(item, text);
                        nodeMap.put(item, tableNode);
                        child = tableNode;
                    } else {
                        child = new DefaultMutableTreeNode(text);
                    }

                    if (parent instanceof DefaultMutableTreeNode) {
                        ((DefaultMutableTreeNode) parent).add(child);
                    } else {
                        throw new UnsupportedOperationException();
                    }
                }

                parent = child;
            }
        }

        if (treeRoot.getChildCount() <= 0 && search != null) {
            DefaultMutableTreeNode noResults = new DefaultMutableTreeNode("No results");
            treeRoot.add(noResults);
        }

        return treeRoot;
    }

    private void search(String searchText) {
        if (!searchText.isEmpty()) {
            tree.setModel(new DefaultTreeModel(buildModel(searchText)));
            expandAll();
        } else {
            tree.setModel(defaultModel);
            reexpand();
        }

        tree.revalidate();
        getComponent().repaint();
    }

    public void expandAll() {
        for (TreeTab.Item item : nodeMap.keySet()) {
            tree.makeVisible(getPath(item));
        }
    }

    public void expandAll(TreeNode node) {
        TreePath path = getPath(node);
        if (path != null) {
            tree.expandPath(path);
        }

        Enumeration<? extends TreeNode> children = node.children();
        if (children != null) {
            children.asIterator().forEachRemaining(this::expandAll);
        }

        tree.revalidate();
        getComponent().repaint();
    }

    public List<TreePath> getPathsUnder(TreePath path) {
        List<TreePath> paths = new ArrayList<>();
        TreeNode node = (TreeNode) path.getLastPathComponent();

        if (!node.getAllowsChildren()) {
            return paths;
        }

        for (TreeNode child : Collections.list(node.children())) {
            TreePath childPath = getPath(child);
            paths.add(childPath);
            paths.addAll(getPathsUnder(childPath));
        }

        return paths;
    }

    public List<TreeTab.Item> getItemsUnder(TreeNode node) {
        if (node == null ){
            return Collections.emptyList();
        } else if (node instanceof TreeTab.LeafNode<?> leafNode) {
            return Collections.singletonList(leafNode.getItem());
        }

        List<TreeTab.Item> tables = new ArrayList<>();
        Enumeration<? extends TreeNode> children = node.children();
        if (children != null) {
            children.asIterator().forEachRemaining(child -> tables.addAll(getItemsUnder(child)));
        }

        return tables;
    }

    @SuppressWarnings("unchecked")
    public <T extends TreeTab.Item> List<T> getItemsUnder(Class<T> type, TreeNode node) {
        return getItemsUnder(node).stream()
                .filter(n -> type.isAssignableFrom(n.getClass()))
                .map(n -> (T) n)
                .toList();
    }

    public TreeTab.Item getSelectedItem() {
        return getItem((TreeNode) tree.getLastSelectedPathComponent());
    }

    public void focusSearch() {
        searchField.grabFocus();
    }

    @Override
    public void mouseClicked(MouseEvent e) {
        if (e.getClickCount() != 2) {
            return;
        }

        int selRow = tree.getClosestRowForLocation(e.getX(), e.getY());
        TreePath selPath = tree.getSelectionPath();
        if (tree.getRowForPath(selPath) != selRow) {
            return;
        }

        if (selPath != null && e.getButton() == MouseEvent.BUTTON1) {
            open(selPath);
        }
    }

    @Override
    public void mousePressed(MouseEvent e) {
        // Popups: OSX will be isPopupTrigger=true, on Windows e.getButton() will == BUTTON3
        if (e.isPopupTrigger() || e.getButton() == MouseEvent.BUTTON3) {
            int selRow = tree.getClosestRowForLocation(e.getX(), e.getY());
            TreePath selPath = tree.getPathForLocation(e.getX(), e.getY());
            if (selPath != null) {
                tree.setSelectionPath(selPath);
            } else if (selRow > -1) {
                tree.setSelectionRow(selRow);
            }

            tree.grabFocus();

            JPopupMenu menu =  tree.getComponentPopupMenu();
            if (menu != null) {
                menu.show(tree, e.getX(), e.getY());
            }
        }

        // Bugfix for UI elements that seemingly repaint in a strange way
        this.getComponent().repaint();
    }

    @Override
    public void mouseReleased(MouseEvent e) {
        // Bugfix for UI elements that seemingly repaint in a strange way
        this.getComponent().repaint();
    }

    @Override
    public void mouseEntered(MouseEvent e) {

    }

    @Override
    public void mouseExited(MouseEvent e) {

    }

    private class TransferHandler extends javax.swing.TransferHandler {
        @Override
        public int getSourceActions(JComponent c) {
            return COPY_OR_MOVE;
        }

        @Override
        public Image getDragImage() {
            TreePath path = tree.getSelectionPath();
            if (path == null) {
                return super.getDragImage();
            }
            Component component = tree.getCellRenderer().getTreeCellRendererComponent
                    (tree, path.getLastPathComponent(),
                            false, false, true, tree.getMinSelectionRow(),
                            false);

            BufferedImage bufferedImage = new BufferedImage(
                    component.getPreferredSize().width,
                    component.getPreferredSize().height,
                    BufferedImage.TYPE_INT_ARGB);

            component.setBounds(0, 0, bufferedImage.getWidth(), bufferedImage.getHeight());

            Graphics g = bufferedImage.getGraphics();
            if (g instanceof Graphics2D g2d) {
                g2d.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY);
                g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2d.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
                g2d.setRenderingHint(RenderingHints.KEY_ALPHA_INTERPOLATION,
                        RenderingHints.VALUE_ALPHA_INTERPOLATION_QUALITY);
            }
            component.paint(g);

            return bufferedImage;
        }

        @Nullable
        @Override
        protected Transferable createTransferable(JComponent c) {
            Item item = getSelectedItem();

            return new Transferable() {
                @Override
                public DataFlavor[] getTransferDataFlavors() {
                    return new DataFlavor[] { ITEM_DATA_FLAVOR };
                }

                @Override
                public boolean isDataFlavorSupported(DataFlavor flavor) {
                    return flavor == ITEM_DATA_FLAVOR;
                }

                @NotNull
                @Override
                public Object getTransferData(DataFlavor flavor) throws UnsupportedFlavorException {
                    if (flavor != ITEM_DATA_FLAVOR) {
                        throw new UnsupportedFlavorException(flavor);
                    }

                    return item;
                }
            };
        }
    }

    /**
     * An interface to type items used by this tree tab.
     */
    public interface Item {

        /**
         * Gets the name shown in the tree for this item.
         * @return item name.
         */
        String getTreeName();

        default String getTreeLeafName() {
            String[] parts = getTreeName().split("-");
            return parts[parts.length - 1].trim();
        }

        /**
         * Gets the icon shown in the tree for this item.
         * @return icon, or null if no icon should be shown.
         */
        Ikon getTreeIcon();

        /**
         * Gets the color shown for this item's icon in a tree.
         * @return icon color.
         */
        default Color getTreeIconColor() {
            return getTreeColor();
        }

        /**
         * Gets the color shown for this item in a tree.
         * @return text color.
         */
        default Color getTreeColor() {
            return Fonts.getTextColor();
        }

        /**
         * Gets the ordinal sorting number for this item.
         * @return ordinal.
         */
        default int getTreeOrdinal() {
            return 4;
        }

        default boolean isVariantSupported(Variant variant) {
            return true;
        }

        default boolean isVariantSupported(Calibration calibration) {
            return isVariantSupported(calibration.getVariant());
        }

    }

    public static class LeafNode<T extends Item> implements MutableTreeNode {
        private final T item;
        private final String text;
        private TreeNode parent;

        private LeafNode(T item, String text) {
            this.item = item;
            this.text = text;
        }

        @Override
        public TreeNode getChildAt(int childIndex) {
            return null;
        }

        @Override
        public int getChildCount() {
            return 0;
        }

        @Override
        public TreeNode getParent() {
            return parent;
        }

        @Override
        public int getIndex(TreeNode node) {
            return 0;
        }

        @Override
        public boolean getAllowsChildren() {
            return false;
        }

        @Override
        public boolean isLeaf() {
            return true;
        }

        @Override
        public Enumeration<? extends TreeNode> children() {
            return null;
        }

        @Override
        public void insert(MutableTreeNode child, int index) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void remove(int index) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void remove(MutableTreeNode node) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void setUserObject(Object object) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void removeFromParent() {
            throw new UnsupportedOperationException();
        }

        @Override
        public void setParent(MutableTreeNode newParent) {
            this.parent = newParent;
        }

        @Override
        public String toString() {
            return text;
        }

        @Override
        public int hashCode() {
            return item.hashCode();
        }

        @Override
        public boolean equals(Object obj) {
            if (obj instanceof LeafNode) {
                return equals((LeafNode<?>) obj);
            } else {
                return super.equals(obj);
            }
        }

        public boolean equals(LeafNode<?> obj) {
            return obj.item.equals(item);
        }

        public T getItem() {
            return item;
        }
    }

    private static class Renderer extends DefaultTreeCellRenderer {
        private final Editor editor;

        private Renderer(Editor editor) {
            this.editor = editor;
        }

        @Override
        public Component getTreeCellRendererComponent(JTree tree, Object value, boolean sel, boolean expanded,
                                                      boolean leaf, int row, boolean hasFocus) {
            JLabel label = (JLabel) super.getTreeCellRendererComponent(tree, value, sel, expanded, leaf, row, hasFocus);

            if (value instanceof LeafNode<?> node) {
                Item item = node.getItem();


                label.setForeground(
                        item.isVariantSupported(editor.getVariant()) ? new JLabel().getForeground() : Color.GRAY);

                if (item != null) {
                    Ikon icon = item.getTreeIcon();
                    if (icon != null) {
                        label.setIcon(Icons.get(icon, item.getTreeIconColor()));
                    } else {
                        label.setIcon(null);
                    }
                }
            } else if (value != tree.getModel().getRoot()) {
                label.setIcon(Icons.get(CarbonIcons.FOLDER));
            }

            return label;
        }
    }
}
