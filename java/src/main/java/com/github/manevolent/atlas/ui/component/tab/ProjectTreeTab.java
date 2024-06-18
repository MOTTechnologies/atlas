package com.github.manevolent.atlas.ui.component.tab;

import com.github.manevolent.atlas.model.*;
import com.github.manevolent.atlas.logging.Log;
import com.github.manevolent.atlas.model.node.GraphModule;
import com.github.manevolent.atlas.ui.behavior.CalibrationListener;
import com.github.manevolent.atlas.ui.behavior.ChangeType;
import com.github.manevolent.atlas.ui.behavior.Model;
import com.github.manevolent.atlas.ui.component.Window;
import com.github.manevolent.atlas.ui.component.popupmenu.tree.ProjectTreePopupMenu;

import com.github.manevolent.atlas.ui.util.Icons;
import com.github.manevolent.atlas.ui.Editor;
import com.github.manevolent.atlas.ui.util.Inputs;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import javax.swing.*;
import javax.swing.tree.*;
import java.util.*;
import java.util.List;
import java.util.logging.Level;
import java.util.regex.Pattern;

import static com.github.manevolent.atlas.ui.util.Fonts.getTextColor;
import static javax.swing.JOptionPane.QUESTION_MESSAGE;

public class ProjectTreeTab extends TreeTab implements CalibrationListener {
    private ProjectTreePopupMenu popupMenu;

    public ProjectTreeTab(Editor form, JTabbedPane tabbedPane) {
        super(form, tabbedPane);
    }

    @Override
    public String getTitle() {
        return "Project Tree";
    }

    @Override
    public Icon getIcon() {
        return Icons.get(CarbonIcons.TREE_VIEW, getTextColor());
    }

    @Override
    public List<TreeTab.Item> getItems() {
        List<TreeTab.Item> items = new ArrayList<>();
        items.addAll(getProject().getTables());
        items.addAll(getProject().getParameters());
        items.addAll(getProject().getScales());
        items.addAll(getProject().getGraphModules());
        return items;
    }

    @Override
    public void openItem(TreeTab.Item item) {
        if (item instanceof Table table) {
            getEditor().openTable(table);
        } else if (item instanceof MemoryParameter parameter) {
            getEditor().openParameter(parameter);
        } else if (item instanceof Scale scale) {
            getEditor().openScale(scale);
        } else if (item instanceof GraphModule module) {
            getEditor().openGraph(module);
        }
    }

    @Override
    protected void preInitComponent(JPanel component) {
        super.preInitComponent(component);
    }

    @Override
    protected void initComponent(JPanel panel) {
        super.initComponent(panel);

        popupMenu = new ProjectTreePopupMenu(this);
    }

    @Override
    protected JPopupMenu getPopupMenu(TreeNode node) {
        popupMenu.update();
        return popupMenu.getComponent();
    }

    public void renameFolder(TreeNode node) {
        if (node == null) {
            return;
        }

        List<Item> items = getItemsUnder(node);
        if (items.isEmpty()) {
            return;
        }

        String oldFolderName = getSelectedFolderName();
        String folderName = (String) Inputs.showRenameDialog(getEditor(),
                "Specify a new name", "Rename Folder", oldFolderName);

        if (folderName == null || folderName.isBlank()) {
            return;
        }

        items.forEach(item -> {
            if (item instanceof Table table) {
                String newName = table.getName().replaceFirst("^" + Pattern.quote(oldFolderName), folderName);
                table.setName(newName);
                getEditor().fireModelChange(Model.TABLE, ChangeType.MODIFIED);
            } else if (item instanceof MemoryParameter parameter) {
                String newName = parameter.getName().replaceFirst("^" + Pattern.quote(oldFolderName), folderName);
                parameter.setName(newName);
                getEditor().fireModelChange(Model.PARAMETER, ChangeType.MODIFIED);
            } else if (item instanceof Scale scale) {
                String newName = scale.getName().replaceFirst("^" + Pattern.quote(oldFolderName), folderName);
                scale.setName(newName);
                getEditor().fireModelChange(Model.FORMAT, ChangeType.MODIFIED);
            } else if (item instanceof GraphModule module) {
                String newName = module.getName().replaceFirst("^" + Pattern.quote(oldFolderName), folderName);
                module.setName(newName);
                getEditor().fireModelChange(Model.GRAPH, ChangeType.MODIFIED);
            }
        });
    }

    public void renameItem(Item item) {
        if (item == null) {
            return;
        }

        String type;
        String oldName;

        if (item instanceof Table table) {
            item = table;
            type = "Table";
            oldName = table.getName();
        } else if (item instanceof MemoryParameter parameter) {
            item = parameter;
            type = "Parameter";
            oldName = parameter.getName();
        } else if (item instanceof Scale scale) {
            item = scale;
            type = "Format";
            oldName = scale.getName();
        } else if (item instanceof GraphModule graphModule) {
            item = graphModule;
            type = "Graph";
            oldName = graphModule.getName();
        } else {
            return;
        }

        String newName = (String) Inputs.showRenameDialog(getEditor(),
                "Specify a new name", "Rename " + type, oldName);

        if (newName == null || newName.isBlank() || oldName.equals(newName)) {
            return;
        }

        if (item instanceof Table table) {
            table.setName(newName);
            getEditor().fireModelChange(Model.TABLE, ChangeType.MODIFIED);
        } else if (item instanceof MemoryParameter parameter) {
            parameter.setName(newName);
            getEditor().fireModelChange(Model.PARAMETER, ChangeType.MODIFIED);
        } else if (item instanceof Scale scale) {
            scale.setName(newName);
            getEditor().fireModelChange(Model.FORMAT, ChangeType.MODIFIED);
        } else if (item instanceof GraphModule graphModule) {
            graphModule.setName(newName);
            getEditor().fireModelChange(Model.GRAPH, ChangeType.MODIFIED);
        }
    }

    public void deleteFolder(TreeNode node) {
        if (node == null || node instanceof TreeTab.LeafNode<?>) {
            return;
        }

        List<Item> items = getItemsUnder(node);
        if (items.isEmpty()) {
            return;
        }

        List<Window> openedWindows = new ArrayList<>();

        getItemsUnder(Table.class, node).stream()
                .flatMap(table -> getParent().getOpenWindows(table).stream())
                .forEach(openedWindows::add);

        getItemsUnder(MemoryParameter.class, node).stream()
                .flatMap(parameter -> getParent().getOpenWindows(parameter).stream())
                .forEach(openedWindows::add);

        if (!openedWindows.stream().allMatch(Window::close)) {
            return;
        }

        if (JOptionPane.showConfirmDialog(getParent(),
                "Are you sure you want to delete " + items.size() + " items(s)?",
                "Delete Folder",
                JOptionPane.YES_NO_OPTION) != JOptionPane.YES_OPTION) {
            return;
        }

        items.forEach(item -> {
            if (item instanceof Table table) {
                getParent().getProject().removeTable(table);
                Log.ui().log(Level.INFO, "Removed " + table.getName());
                getEditor().fireModelChange(Model.TABLE, ChangeType.REMOVED);
            } else if (item instanceof MemoryParameter parameter) {
                getParent().getProject().removeParameter(parameter);
                Log.ui().log(Level.INFO, "Removed " + parameter.getName());
                getEditor().fireModelChange(Model.PARAMETER, ChangeType.REMOVED);
            } else if (item instanceof Scale scale) {
                getParent().getProject().removeScale(scale);
                Log.ui().log(Level.INFO, "Removed " + scale.getName());
                getEditor().fireModelChange(Model.FORMAT, ChangeType.REMOVED);
            }
        });
    }

    public void define(TreePath selPath) {
        if (selPath == null) {
            return;
        }

        Object last = selPath.getLastPathComponent();
        if (last instanceof TreeTab.LeafNode<?> leafNode) {
            define(leafNode.getItem());
        }
    }

    public void define(Item item) {
        if (item instanceof Table table) {
            getParent().openTableDefinition(table);
        } else if (item instanceof MemoryParameter parameter) {
            getParent().openParameter(parameter);
        } else if (item instanceof Scale scale) {
            getParent().openScale(scale);
        } else if (item instanceof GraphModule module) {
            getParent().openGraph(module);
        }
    }

    public void defineCopy(TreePath selPath) {
        if (selPath == null) {
            return;
        }

        Object last = selPath.getLastPathComponent();
        if (last instanceof TreeTab.LeafNode<?> leafNode) {
            defineCopy(leafNode);
        }
    }

    public void defineCopy(LeafNode<?> leafNode) {
        Item item = leafNode.getItem();
        String type;
        String name;

        if (item instanceof Table table) {
            item = table.copy();
            type = "Table";
            name = table.getName();
        } else if (item instanceof MemoryParameter parameter) {
            item = parameter.copy();
            type = "Parameter";
            name = parameter.getName();
        } else if (item instanceof Scale scale) {
            item = scale.copy();
            type = "Format";
            name = scale.getName();
        } else {
            return;
        }

        String newName = (String) Inputs.showRenameDialog(getEditor(),
                "Specify a name", "Copy " + type, name + " (Copy)");

        if (newName == null || newName.isBlank()) {
            return;
        }

        if (item instanceof Table table) {
            table.setName(newName);
        } else if (item instanceof MemoryParameter parameter) {
            parameter.setName(newName);
        } else if (item instanceof Scale scale) {
            scale.setName(newName);
        }

        define(item);
    }

    @Override
    public void onModelChanged(Model model, ChangeType changeType) {
        super.onModelChanged(model, changeType);

        if (model == Model.TABLE || model == Model.PARAMETER || model == Model.FORMAT || model == Model.GRAPH) {
            update();
        }
    }

    private String getSelectedFolderName() {
        TreeNode node = (TreeNode) getTree().getLastSelectedPathComponent();;
        List<String> nodeNames = new ArrayList<>();
        while (node != null) {
            if (node == getTree().getModel().getRoot()) {
                break;
            }

            if (node instanceof DefaultMutableTreeNode) {
                nodeNames.addFirst(node.toString());
            }

            node = node.getParent();
        }

        return String.join(" - ", nodeNames);
    }

    public <T extends Item> T newItem(Class<T> type) {
        String name;
        String typeName;

        if (type.equals(Table.class)) {
            typeName = "Table";
        } else if (type.equals(MemoryParameter.class)) {
            typeName = "Parameter";
        } else if (type.equals(Scale.class)) {
            typeName = "Format";
        } else if (type.equals(GraphModule.class)) {
            typeName = "Graph";
        } else {
            throw new UnsupportedOperationException(type.getName());
        }

        name = "New " + typeName;
        String folderName = getSelectedFolderName();
        if (!folderName.isEmpty()) {
            name = folderName + " - " + name;
        }

        name = (String) Inputs.showRenameDialog(getEditor(), "Specify a name", "New " + typeName, name);

        if (name == null || name.isBlank()) {
            return null;
        }

        Item item;
        if (type.equals(Table.class)) {
            Table table = Table.builder()
                    .withName(name)
                    .withData(Series.builder()
                            .withAddress(getEditor().getDefaultMemoryAddress(MemoryType.CODE))
                            .withLength(1)
                            .withScale(Scale.getNone(DataFormat.UBYTE)))
                    .build();

            table.setup(getProject());

            item = table;
        } else if (type.equals(MemoryParameter.class)) {
            MemoryAddress address = getEditor().getDefaultMemoryAddress(MemoryType.CODE);
            item = MemoryParameter.builder()
                    .withName(name)
                    .withAddress(address)
                    .withScale(Scale.getNone(DataFormat.UBYTE))
                    .build();
        } else if (type.equals(Scale.class)) {
            Scale newScale = new Scale();
            newScale.setUnit(Unit.NONE);
            newScale.setFormat(DataFormat.UBYTE);
            newScale.setOperations(new ArrayList<>());
            newScale.setName(name);

            item = newScale;
        } else if (type.equals(GraphModule.class)) {
            GraphModule newGraph = new GraphModule();
            newGraph.setName(name);

            item = newGraph;

            getProject().addGraphModule(newGraph);
            getEditor().fireModelChange(Model.GRAPH, ChangeType.ADDED);
        } else {
            throw new UnsupportedOperationException(type.getName());
        }

        define(item);

        //noinspection unchecked
        return (T) item;
    }

    public void deleteItem(Item selectedItem) {
        String name;
        String typeName;
        if (selectedItem instanceof Table table) {
            typeName = "Table";
            name = table.getName();
        } else if (selectedItem instanceof MemoryParameter parameter) {
            typeName = "Parameter";
            name = parameter.getName();
        } else if (selectedItem instanceof Scale scale) {
            typeName = "Format";
            name = scale.getName();
        } else if (selectedItem instanceof GraphModule graph) {
            typeName = "Graph";
            name = graph.getName();
        } else {
            return;
        }

        if (JOptionPane.showConfirmDialog(getParent(),
                "Are you sure you want to delete " + name + "?",
                "Delete " + typeName,
                JOptionPane.YES_NO_OPTION) != JOptionPane.YES_OPTION) {
            return;
        }

        if (selectedItem instanceof Table table) {
            getProject().removeTable(table);
            getEditor().fireModelChange(Model.TABLE, ChangeType.REMOVED);
        } else if (selectedItem instanceof MemoryParameter parameter) {
            getProject().removeParameter(parameter);
            getEditor().fireModelChange(Model.PARAMETER, ChangeType.REMOVED);
        } else if (selectedItem instanceof Scale scale) {
            getProject().removeScale(scale);
            getEditor().fireModelChange(Model.FORMAT, ChangeType.REMOVED);
        } else if (selectedItem instanceof GraphModule module) {
            getProject().removeGraphModule(module);
            getEditor().fireModelChange(Model.GRAPH, ChangeType.REMOVED);
        }
    }

    @Override
    public void onCalibrationChanged(Calibration oldCalibration, Calibration newCalibration) {
        update();
    }
}
