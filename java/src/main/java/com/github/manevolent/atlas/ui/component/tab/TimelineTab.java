package com.github.manevolent.atlas.ui.component.tab;

import com.github.manevolent.atlas.ui.Editor;
import com.github.manevolent.atlas.ui.component.toolbar.ConsoleTabToolbar;
import com.github.manevolent.atlas.ui.util.Icons;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import javax.swing.*;
import java.awt.*;

import static com.github.manevolent.atlas.ui.util.Fonts.getTextColor;

public class TimelineTab extends Tab {
    private ConsoleTabToolbar toolbar;

    public TimelineTab(Editor editor, JTabbedPane tabbedPane) {
        super(editor, tabbedPane);
    }

    @Override
    public String getTitle() {
        return "Timeline";
    }

    @Override
    public Icon getIcon() {
        return Icons.get(CarbonIcons.TIME_PLOT, getTextColor());
    }

    @Override
    protected void preInitComponent(JPanel component) {
    }

    @Override
    protected void initComponent(JPanel panel) {
        panel.setLayout(new BorderLayout());
    }

}
