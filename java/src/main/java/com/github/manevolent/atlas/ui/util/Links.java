package com.github.manevolent.atlas.ui.util;

import com.github.manevolent.atlas.logging.Log;

import java.awt.*;
import java.net.URI;
import java.util.logging.Level;

public class Links {

    public static boolean open(URI uri) {
        Desktop desktop = Desktop.isDesktopSupported() ? Desktop.getDesktop() : null;
        if (desktop != null && desktop.isSupported(Desktop.Action.BROWSE)) {
            try {
                desktop.browse(uri);
                return true;
            } catch (Exception e) {
                Log.ui().log(Level.WARNING, "Problem opening " + uri.toASCIIString(), e);
            }
        }
        return false;
    }

}
