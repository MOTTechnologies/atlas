package com.github.manevolent.atlas.ui.component.popupmenu.tree;

import com.github.manevolent.atlas.model.*;
import com.github.manevolent.atlas.model.node.GraphModule;
import com.github.manevolent.atlas.model.node.GraphNode;
import com.github.manevolent.atlas.model.node.ParameterNode;
import com.github.manevolent.atlas.model.node.TableNode;
import com.github.manevolent.atlas.ui.Editor;
import com.github.manevolent.atlas.ui.component.popupmenu.PopupMenu;
import com.github.manevolent.atlas.ui.component.tab.ProjectTreeTab;
import com.github.manevolent.atlas.ui.component.tab.TreeTab;
import com.github.manevolent.atlas.ui.component.table.TableEditor;
import com.github.manevolent.atlas.ui.util.Errors;
import com.github.manevolent.atlas.ui.util.Menus;
import com.github.manevolent.atlas.ui.util.Tools;
import org.kordamp.ikonli.carbonicons.CarbonIcons;
import org.kordamp.ikonli.fontawesome5.FontAwesomeSolid;

import javax.swing.*;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreeNode;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.util.List;

public class ProjectTreePopupMenu extends PopupMenu<ProjectTreeTab> {
    public ProjectTreePopupMenu(ProjectTreeTab editor) {
        super(editor);
    }

    @Override
    public Editor getEditor() {
        return getParent().getEditor();
    }

    @Override
    protected void initComponent(JPopupMenu menu) {
        ProjectTreeTab tab = getParent();
        JTree tree = tab.getTree();
        TreeNode selectedNode = (TreeNode) tree.getLastSelectedPathComponent();
        TreeTab.Item selectedItem = tab.getItem(selectedNode);

        JMenu newMenu = new JMenu("New");
        newMenu.add(Menus.item(CarbonIcons.DATA_TABLE_REFERENCE, Table.codeColor, "Table", e -> getEditor().newTable()));
        newMenu.add(Menus.item(CarbonIcons.CHART_CUSTOM, MemoryParameter.treeColor, "Parameter", e -> getEditor().newParameter()));
        newMenu.add(Menus.item(CarbonIcons.DATA_SET, Scale.treeColor, "Format", e -> getEditor().newFormat()));
        newMenu.add(Menus.item(CarbonIcons.DATA_VIS_3, GraphModule.treeColor, "Graph", e -> getEditor().newGraph()));
        menu.add(newMenu);

        if (selectedItem != null || selectedNode != null) {
            menu.addSeparator();
        }

        if (selectedItem != null) {
            if (selectedItem instanceof Table) {
                menu.add(Menus.item(CarbonIcons.LAUNCH, "Open " + selectedNode.toString(),
                        e -> tab.openItem(selectedItem)));
            }

            menu.add(Menus.item(selectedItem.getTreeIcon(), selectedItem.getTreeIconColor(), "Edit " + selectedNode.toString(),
                    e -> tab.define(selectedItem)));

            menu.addSeparator();
        }

        if (selectedItem instanceof MemoryParameter parameter) {
            menu.add(Menus.item(CarbonIcons.ADD, "Add to Gauge Set",
                    e -> getEditor().getGaugesTab().addGauge(parameter)));
        }

        if (selectedItem instanceof Scale scale) {
            menu.add(Menus.item(FontAwesomeSolid.VIAL, "Test Value...",
                    e -> Tools.testOperation(getEditor(), scale)));
        } else if (selectedItem instanceof MemoryParameter parameter) {
            Variant variant = getEditor().getVariant();

            menu.add(Menus.item(FontAwesomeSolid.COPY, "Copy Address (" + variant.getName() + ")", e -> {
                MemoryAddress address = parameter.getAddress();
                if (!address.hasOffset(variant)) {
                    Errors.show(getEditor(), "Copy memory address failed",
                            "Failed to copy memory address for \"" + parameter.getName() + "\"!\r\n" +
                                    "This parameter does not support the " +
                                    "current variant (" + variant.getName() + ").");
                    return;
                }

                String addressString = address.toString(variant);

                Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                clipboard.setContents(new StringSelection(addressString), null);
            }));

            menu.addSeparator();

            Scale scale = parameter.getScale();

            menu.add(Menus.item(scale.getTreeIcon(), scale.getTreeIconColor(),
                    "Edit " + scale.getTreeLeafName(), e -> tab.define(scale)));

            menu.add(Menus.item(FontAwesomeSolid.VIAL, "Test Value...",
                    e -> Tools.testOperation(getEditor(), parameter.getScale())));

            menu.addSeparator();
        }

        if (selectedItem instanceof Table table) {
            GraphNode node = getProject().getGraphNodes().stream()
                    .filter(m -> m instanceof TableNode tableNode && tableNode.getTable() == table)
                    .findFirst().orElse(null);

            if (node != null) {
                menu.add(Menus.item(CarbonIcons.SEARCH, GraphModule.treeColor,
                        "Find in Graph", e -> getEditor().openNode(node)));
                menu.addSeparator();
            }
        }

        if (selectedItem instanceof MemoryParameter parameter) {
            java.util.List<GraphNode> nodes = getProject().getGraphNodes().stream()
                    .filter(m -> m instanceof ParameterNode pnode && pnode.getParameter() == parameter)
                    .toList();

            if (nodes.size() == 1) {
                menu.add(Menus.item(CarbonIcons.SEARCH,  GraphModule.treeColor,
                        "Find in Graph", e -> getEditor().openNode(nodes.getFirst())));
                menu.addSeparator();
            }
        }

        if (selectedItem != null) {
            menu.add(Menus.item(CarbonIcons.EDIT, "Rename...", e -> tab.renameItem(selectedItem)));
        } else if (selectedNode != null) {
            menu.add(Menus.item(CarbonIcons.EDIT, "Rename...", e -> tab.renameFolder(selectedNode)));
        }

        if (selectedNode instanceof TreeTab.LeafNode<?> leafNode) {
            menu.add(Menus.item(CarbonIcons.COPY, "Copy...", e -> tab.defineCopy(leafNode)));
        }

        if (selectedItem != null) {
            menu.add(Menus.item(CarbonIcons.DELETE, "Delete", e -> tab.deleteItem(selectedItem)));
        } else if (selectedNode != null) {
            menu.add(Menus.item(CarbonIcons.DELETE, "Delete", e -> tab.deleteFolder(selectedNode)));
        }

        if (selectedNode instanceof DefaultMutableTreeNode) {
            menu.addSeparator();

            menu.add(Menus.item(CarbonIcons.EXPAND_ALL, "Expand All", e -> {
                TreeNode selected = (TreeNode) tree.getLastSelectedPathComponent();
                tab.expandAll(selected);
            }));
        }

        if (selectedItem instanceof Table table) {
            menu.addSeparator();

            menu.add(Menus.item(CarbonIcons.EXPORT, "Export Table...", e -> {
                TableEditor.exportTable(getEditor(), table, getEditor().getCalibration());
            }));
        }

        // Folder operations
        if (selectedItem == null) {
            menu.addSeparator();


            menu.add(Menus.item(CarbonIcons.FETCH_UPLOAD, "Apply Other Calibration...", (event) ->
                    applyCalibration(event, tab.getItemsUnder(selectedNode))));
        }
    }

    private void applyCalibration(ActionEvent event, List<TreeTab.Item> itemsUnder) {
        Tools.applyCalibration(getEditor(), itemsUnder::contains);
    }

    public void update() {
        reinitialize();
    }
}
