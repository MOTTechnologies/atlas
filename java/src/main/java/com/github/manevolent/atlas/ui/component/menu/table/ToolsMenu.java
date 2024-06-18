package com.github.manevolent.atlas.ui.component.menu.table;

import com.github.manevolent.atlas.model.Table;
import com.github.manevolent.atlas.model.node.GraphNode;
import com.github.manevolent.atlas.model.node.TableNode;
import com.github.manevolent.atlas.ui.Editor;
import com.github.manevolent.atlas.ui.component.table.TableEditor;
import com.github.manevolent.atlas.ui.util.Errors;
import com.github.manevolent.atlas.ui.util.Menus;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import javax.swing.*;

import static com.github.manevolent.atlas.ui.component.table.TableComparer.CompareOperation.SUBTRACT;
import static com.github.manevolent.atlas.ui.component.table.TableComparer.CompareOperation.SUM;

public class ToolsMenu extends TableEditorMenu {
    public ToolsMenu(TableEditor editor) {
        super(editor);
    }

    @Override
    public Editor getEditor() {
        return getParent().getEditor();
    }

    public Table getTable() {
        return getParent().getTable();
    }

    @Override
    protected void initComponent(JMenu menu) {
        menu.setText("Tools");

        menu.add(Menus.item(CarbonIcons.DATA_UNSTRUCTURED, "Compare with Table...", e -> {
            getParent().compareWithTable(SUBTRACT);
        }));

        menu.add(Menus.item(CarbonIcons.DATA_UNSTRUCTURED, "Sum with Table...", e -> {
            getParent().compareWithTable(SUM);
        }));

        menu.add(Menus.item(CarbonIcons.DATA_SHARE, "Compare with Calibration...", e -> {
            getParent().compareWithCalibration();
        }));

        menu.addSeparator();

        menu.add(Menus.item(CarbonIcons.QUERY, "Locate in ROM", (e) -> getParent().findTable()));

        menu.add(Menus.item(CarbonIcons.SEARCH, "Locate in Graph", e -> {
            GraphNode node = getProject().getGraphNodes().stream()
                    .filter(m -> m instanceof TableNode tableNode && tableNode.getTable() == getTable())
                    .findFirst().orElse(null);

            if (node != null) {
                getEditor().openNode(node);
            } else {
                Errors.show(getEditor(), "Table Not Found", getTable().getName() + " is not defined in any node graph.");
            }
        }));
    }
}
