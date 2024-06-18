package com.github.manevolent.atlas.ui;

import com.formdev.flatlaf.FlatDarculaLaf;
import com.github.manevolent.atlas.ApplicationMetadata;
import com.github.manevolent.atlas.ghidra.AtlasGhidraApplicationLayout;
import com.github.manevolent.atlas.ghidra.AtlasLogger;
import com.github.manevolent.atlas.model.Project;
import com.github.manevolent.atlas.logging.Log;
import com.github.manevolent.atlas.model.storage.ProjectStorage;
import com.github.manevolent.atlas.model.storage.ProjectStorageType;
import com.github.manevolent.atlas.settings.Settings;
import com.github.manevolent.atlas.ui.util.Icons;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.util.Msg;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.util.logging.Level;

public class Atlas {

    private static void setupTheme() {
        JFrame.setDefaultLookAndFeelDecorated(true);
        JDialog.setDefaultLookAndFeelDecorated(true);
        System.setProperty("flatlaf.useWindowDecorations", "false");
        System.setProperty("apple.laf.useScreenMenuBar", "true");

        try {
            final Taskbar taskbar = Taskbar.getTaskbar();

            if (taskbar.isSupported(Taskbar.Feature.ICON_IMAGE)) {
                taskbar.setIconImage(Icons.getImage(CarbonIcons.METER_ALT, Color.WHITE, 128).getImage());
            }
        } catch (Exception e) {
            Log.ui().log(Level.WARNING, "Problem setting taskbar icon", e);
        }

        FlatDarculaLaf.setup();
        UIManager.put("Tree.repaintWholeRow", true);
    }

    private static void setupGhidra() throws IOException {
        Application.initializeApplication(new AtlasGhidraApplicationLayout(), new ApplicationConfiguration());
        Msg.setErrorLogger(new AtlasLogger());
    }

    public static void main(String[] args) throws Exception {
        System.setProperty("sun.awt.exception.handler", AwtExceptionHandler.class.getName());
        System.setProperty("org.graphstream.ui", "swing");
        System.setProperty("apple.awt.application.appearance", "system");
        System.setProperty("com.apple.mrj.application.apple.menu.about.name", ApplicationMetadata.getName());

        Log.get().setLevel(Level.FINE);

        SplashForm splashForm = new SplashForm();
        java.awt.EventQueue.invokeLater(() -> {
            splashForm.setVisible(true);
        });

        Thread.sleep(250L);

        splashForm.setProgress(0.1f, "Initializing Ghidra...");
        setupGhidra();

        splashForm.setProgress(0.2f, "Loading settings...");
        Settings.getAll();

        splashForm.setProgress(0.3f, "Loading theme...");
        setupTheme();

        splashForm.setProgress(0.4f, "Loading ROM data...");
        Project project;
        String lastOpenedProject = Settings.LAST_OPENED_PROJECT.get();
        File romFile = null;
        if (lastOpenedProject != null) {
            File lastOpenedProjectFile = new File(lastOpenedProject);
            if (lastOpenedProjectFile.exists()) {
                splashForm.setProgress(0.5f, "Loading " + lastOpenedProjectFile.getName() + "...");

                try {
                    ProjectStorage storage = ProjectStorageType.detect(lastOpenedProjectFile).getStorageFactory()
                            .createStorage();
                    project = storage.load(lastOpenedProjectFile);
                    romFile = lastOpenedProjectFile;

                    Log.ui().log(Level.INFO, "Reopened last project at " +
                            lastOpenedProjectFile.getPath() + ".");
                } catch (Exception ex) {
                    Log.ui().log(Level.SEVERE, "Problem opening last project at " +
                            lastOpenedProjectFile.getPath(), ex);
                    JOptionPane.showMessageDialog(splashForm,
                            "Failed to open project!\r\nSee console output for more details.",
                            "Open failed",
                            JOptionPane.ERROR_MESSAGE);
                    project = Project.builder().build();
                }
            } else {
                project = Project.builder().build();
                Log.ui().log(Level.WARNING, "Last opened project at " +
                        lastOpenedProjectFile.getPath() + " does not exist!");
            }
        } else {
            project = Project.builder().build();
            Log.ui().log(Level.INFO, "Opened a new project.");
        }

        splashForm.setProgress(0.6f, "Initializing UI...");
        Editor editorForm = new Editor(project);

        splashForm.setProgress(0.75f, "Opening Project...");
        if (romFile != null) {
            editorForm.setProjectFile(romFile);
        }

        editorForm.setProject(project);

        splashForm.setProgress(1.0f, "Opening Atlas...");
        Thread.sleep(500L);

        java.awt.EventQueue.invokeLater(() -> {
            editorForm.setVisible(true);
            Log.get().log(Level.FINE, "Application started.");
        });

        java.awt.EventQueue.invokeLater(splashForm::dispose);

        Runtime.getRuntime().addShutdownHook(new Thread(() ->
                editorForm.getConnectionManager().getConnection().ifPresent(connection -> {
            try {
                connection.disconnect();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        })));
    }

}
