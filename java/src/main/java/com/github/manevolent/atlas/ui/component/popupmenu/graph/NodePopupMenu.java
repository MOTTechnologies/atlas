package com.github.manevolent.atlas.ui.component.popupmenu.graph;

import com.github.manevolent.atlas.model.*;
import com.github.manevolent.atlas.model.node.DocumentationNode;
import com.github.manevolent.atlas.model.node.GraphNode;
import com.github.manevolent.atlas.model.node.ParameterNode;
import com.github.manevolent.atlas.model.node.TableNode;
import com.github.manevolent.atlas.ui.Editor;
import com.github.manevolent.atlas.ui.component.graph.DefaultNodeComponent;
import com.github.manevolent.atlas.ui.component.popupmenu.PopupMenu;
import com.github.manevolent.atlas.ui.util.Errors;
import com.github.manevolent.atlas.ui.util.Inputs;
import com.github.manevolent.atlas.ui.util.Menus;
import com.github.manevolent.atlas.ui.util.Tools;
import org.kordamp.ikonli.carbonicons.CarbonIcons;
import org.kordamp.ikonli.fontawesome5.FontAwesomeSolid;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;

public class NodePopupMenu extends PopupMenu<DefaultNodeComponent> {
    public NodePopupMenu(DefaultNodeComponent component) {
        super(component);
    }

    @Override
    public Editor getEditor() {
        return getParent().getEditor();
    }

    @Override
    protected void initComponent(JPopupMenu menu) {
        GraphNode graphNode = getParent().getGraphNode();

        if (graphNode instanceof TableNode tableNode) {
            Table table = tableNode.getTable();

            menu.add(Menus.item(CarbonIcons.DATA_TABLE, table.getTreeIconColor(), "Open Table", (e) -> {
                getEditor().openTable(table);
            }));

            menu.add(Menus.item(CarbonIcons.EDIT, "Edit Table", (e) -> {
                getEditor().openTableDefinition(table);
            }));

            menu.addSeparator();
        } else if (graphNode instanceof ParameterNode parameterNode) {
            MemoryParameter parameter = parameterNode.getParameter();

            menu.add(Menus.item(CarbonIcons.EDIT, parameter.getTreeIconColor(), "Edit Parameter", (e) -> {
                getEditor().openParameter(parameter);
            }));

            menu.addSeparator();

            menu.add(Menus.item(CarbonIcons.ADD, "Add to Gauge Set",
                    e -> getEditor().getGaugesTab().addGauge(parameter)));

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
                    "Edit " + scale.getTreeLeafName(), e -> getEditor().openScale(scale)));

            menu.add(Menus.item(FontAwesomeSolid.VIAL, "Test Value...",
                    e -> Tools.testOperation(getEditor(), parameter.getScale())));

            menu.addSeparator();
        } else if (graphNode instanceof DocumentationNode documentationNode) {
            menu.add(Menus.item(CarbonIcons.SETTINGS_ADJUST, "Resize Inputs...", (e) -> {
                Integer numberInputs = Inputs.showSpinnerDialog(getEditor(), "Resize Inputs",
                        "Specify the number of inputs on this node:", documentationNode.getNumberInputs(), 0, 50);

                if (numberInputs != null) {
                    documentationNode.setNumberInputs(numberInputs);
                    getParent().reload();
                }
            }));

            menu.addSeparator();
        }

        menu.add(Menus.item(CarbonIcons.DELETE, "Delete Node", (e) -> getParent().delete()));
    }
}
