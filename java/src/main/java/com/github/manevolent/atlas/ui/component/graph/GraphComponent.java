package com.github.manevolent.atlas.ui.component.graph;

import javax.swing.*;
import java.awt.*;

public abstract class GraphComponent extends JComponent {

    public abstract Point getGraphMousePosition();

    public abstract java.util.List<NodeComponent> updateVisibleNodes();

}
