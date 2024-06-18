package com.github.manevolent.atlas.ui.component.menu.editor;

import com.github.manevolent.atlas.ApplicationMetadata;
import com.github.manevolent.atlas.ui.Editor;
import com.github.manevolent.atlas.ui.component.Window;
import com.github.manevolent.atlas.ui.util.Icons;
import com.github.manevolent.atlas.ui.util.Links;
import com.github.manevolent.atlas.ui.util.Menus;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import javax.swing.*;
import javax.swing.event.HyperlinkEvent;
import javax.swing.event.HyperlinkListener;
import java.awt.*;
import java.net.URISyntaxException;
import java.util.Collection;

public class HelpMenu extends EditorMenu {
    public HelpMenu(Editor editor) {
        super(editor);
    }

    @Override
    protected void initComponent(JMenu component) {
        super.initComponent(component);
        component.setText("Help");
        update(component);
    }

    public void update() {
        update(getComponent());
    }

    private void update(JMenu menu) {
        // Clear all menu items
        menu.removeAll();




        menu.add(Menus.item("About " + ApplicationMetadata.getName(), (e) -> {
            String text = String.format("<html><h2>%s Open Source</h2>%s<br/><br/>%s<br/>%s<br/><br/>%s<br/>%s<br/><br/>%s</html>",
                    ApplicationMetadata.getName(),
                    "Version " + ApplicationMetadata.getVersion(),
                    "VM: " + System.getProperty("java.vm.name") + " " + System.getProperty("java.vm.version") + " " + System.getProperty("os.arch"),
                    "Memory: " + (Runtime.getRuntime().totalMemory() / 1024L / 1024L) + " of " + (Runtime.getRuntime().maxMemory() / 1024L / 1024L) + "MB",
                    "Created with a passion for you to have free access to tune modern vehicles.",
                    "Licensed under <a href=\"https://www.gnu.org/licenses/agpl-3.0.en.html\">AGPL v3.0</a>",
                    "<a href=\"https://atlasopensource.org/\">atlasopensource.org</a> | <a href=\"https://github.com/atlas-tuning/atlas\">GitHub</a> | <a href=\"https://www.youtube.com/channel/UCySigxPeIk5skENhOMlJ6mw\">YouTube</a> "
            );

            JEditorPane jep = new JEditorPane("text/html", text);
            jep.addHyperlinkListener(e1 -> {
                if (e1.getEventType() != HyperlinkEvent.EventType.ACTIVATED) {
                    return;
                }

                try {
                    Links.open(e1.getURL().toURI());
                } catch (URISyntaxException ex) {
                    throw new RuntimeException(ex);
                }
            });
            jep.setEditable(false);
            jep.setBorder(null);

            JOptionPane.showMessageDialog(getEditor(),
                     jep,
                    "About " + ApplicationMetadata.getName(),
                    JOptionPane.INFORMATION_MESSAGE,
                    Icons.get(CarbonIcons.APPLICATION, 64)
            );
        }));
    }
}
