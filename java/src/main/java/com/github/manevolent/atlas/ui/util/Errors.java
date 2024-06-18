package com.github.manevolent.atlas.ui.util;

import com.github.manevolent.atlas.logging.Log;

import javax.swing.*;
import java.awt.*;
import java.util.logging.Level;

public class Errors {

    public static void show(Component parent, String title, String message, Throwable e) {
        show(parent, title, message, e.getMessage(), e);
    }

    public static void show(Component parent, String title, String header, String message, Throwable e) {
        Log.ui().log(Level.SEVERE, title + ": " + header, e);
        JOptionPane.showMessageDialog(parent, header + "\r\n" + message + "\r\n" +
                "See console output (F12) for more details.", title, JOptionPane.ERROR_MESSAGE);
    }

    public static void show(Component parent, String title, String message) {
        JOptionPane.showMessageDialog(parent, message, title, JOptionPane.ERROR_MESSAGE);
    }

}
