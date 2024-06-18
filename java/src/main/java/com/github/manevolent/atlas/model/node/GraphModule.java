package com.github.manevolent.atlas.model.node;

import com.github.manevolent.atlas.model.AbstractAnchored;
import com.github.manevolent.atlas.ui.component.tab.TreeTab;
import org.kordamp.ikonli.Ikon;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import java.awt.*;

public class GraphModule extends AbstractAnchored implements TreeTab.Item {
    public static Color treeColor = new Color(0xa050ff);

    private String name;

    public GraphModule() {

    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @Override
    public Color getTreeIconColor() {
        return treeColor;
    }

    @Override
    public String getTreeName() {
        return getName();
    }

    @Override
    public Ikon getTreeIcon() {
        return CarbonIcons.DATA_VIS_3;
    }
}
