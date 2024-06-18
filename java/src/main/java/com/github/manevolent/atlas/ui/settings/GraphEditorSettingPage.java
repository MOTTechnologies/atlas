package com.github.manevolent.atlas.ui.settings;

import com.github.manevolent.atlas.settings.Settings;
import com.github.manevolent.atlas.ui.Editor;
import com.github.manevolent.atlas.ui.component.Window;
import com.github.manevolent.atlas.ui.component.graph.GraphEditor;
import com.github.manevolent.atlas.ui.component.table.TableEditor;
import com.github.manevolent.atlas.ui.settings.field.CheckboxSettingField;
import com.github.manevolent.atlas.ui.settings.field.SettingField;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import java.awt.*;
import java.util.List;

public class GraphEditorSettingPage extends BasicSettingPage {
    private final Editor editor;

    public GraphEditorSettingPage(Editor parent) {
        super(parent, CarbonIcons.DATA_VIS_3, "Graph Editor");

        this.editor = parent;
    }

    @Override
    protected List<SettingField> createFields() {
        return List.of(
                new CheckboxSettingField(
                        "Live Parameter Data", "Poll the vehicle for visible parameter values",
                        Settings.GRAPH_EDITOR_LIVE
                ),
                new CheckboxSettingField(
                        "Draw Gridlines", "Draw grid lines in the background of the graph editor",
                        Settings.GRAPH_EDITOR_DRAW_GRID_LINES
                )
        );
    }

    @Override
    public boolean apply() {
        if (super.apply()) {
            editor.getOpenWindows(GraphEditor.class).forEach(Window::reload);
            return true;
        } else {
            return false;
        }
    }
}
