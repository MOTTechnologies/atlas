package com.github.manevolent.atlas.model.storage;

import java.io.File;

public enum ProjectStorageType {
    ZIP(new ZipProjectStorage.Factory()),
    FOLDER(new FolderProjectStorage.Factory());

    private final ProjectStorageFactory factory;

    ProjectStorageType(ProjectStorageFactory factory) {
        this.factory = factory;
    }

    public ProjectStorageFactory getStorageFactory() {
        return factory;
    }

    public static ProjectStorageType detect(File file) {
        if (file.isDirectory()) {
            return FOLDER;
        } else {
            return ZIP;
        }
    }

    public static ProjectStorageType getDefault() {
        return FOLDER;
    }
}
