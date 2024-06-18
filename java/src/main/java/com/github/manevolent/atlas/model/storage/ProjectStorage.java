package com.github.manevolent.atlas.model.storage;

import com.github.manevolent.atlas.model.Project;

import javax.swing.*;
import java.io.File;

import java.io.IOException;

public interface ProjectStorage {

    /**
     * Loads a project from a specified file path.
     * @param file file or directory to load.
     * @return loaded Project instance.
     * @throws IOException if there is a problem reading the project.
     */
    Project load(File file) throws IOException;

    /**
     * Saves a project to a specified file path.
     * @param project Project instance to save.
     * @param file file or directory to save the Project to.
     * @throws IOException if there is a problem saving the project.
     */
    void save(Project project, File file) throws IOException;

    /**
     * Create a dialog for this project storage type.
     * @return JFileChooser instance.
     */
    JFileChooser createFileChooser();

    /**
     * When true, declares that this project storage type should be used when auto-loading in the Editor.
     * @return true if the Editor should automatically load projects of this type when it is re-opened.
     */
    default boolean isAutoLoading() {
        return false;
    }

}
