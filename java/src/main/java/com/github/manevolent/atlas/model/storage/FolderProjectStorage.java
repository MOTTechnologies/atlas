package com.github.manevolent.atlas.model.storage;

import com.github.manevolent.atlas.model.MemorySection;
import com.github.manevolent.atlas.model.source.LazySource;
import com.github.manevolent.atlas.ui.behavior.ProgressListener;
import net.lingala.zip4j.ZipFile;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.io.*;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Objects;
import java.util.stream.Collectors;

public class FolderProjectStorage extends YamlProjectStorage {
    public FolderProjectStorage(ProgressListener listener) {
        super(listener);
    }

    @Override
    protected boolean canWriteConfidentialData() {
        return true;
    }

    @Override
    public boolean isAutoLoading() {
        return true;
    }

    @Override
    protected AbstractProjectStorage.Container openContainerRead(File file) throws IOException {
        if (file.exists() && !file.isDirectory()) {
            throw new IOException(file.getPath() + " is not a directory");
        } else if (!file.exists()) {
            throw new FileNotFoundException(file.getPath());
        }

        return new FolderProjectStorage.FolderContainer(file);
    }

    @Override
    protected AbstractProjectStorage.Container openContainerWrite(File file) throws IOException {
        if (file.exists() && !file.isDirectory()) {
            throw new IOException(file.getPath() + " is not a directory");
        } else if (!file.exists()) {
            file.mkdirs();
        }

        // Ensure .gitignore is generated (confidential files)
        FolderContainer folderContainer = new FolderProjectStorage.FolderContainer(file);

        if (canWriteConfidentialData()) {
            folderContainer.createEntry(".gitignore").withWrite(os -> {
                try (BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(os))) {
                    writer.write("confidential_*\r\n");
                }
            });
        }

        return folderContainer;
    }

    @Override
    public JFileChooser createFileChooser() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        return fileChooser;
    }

    private static class FolderContainer implements AbstractProjectStorage.Container {
        private final File folder;

        private FolderContainer(File folder) {
            this.folder = folder;
        }

        @Override
        public File getFile() {
            return folder;
        }

        @Override
        public Collection<AbstractProjectStorage.Entry> getEntries() throws IOException {
            if (!folder.exists()) {
                return Collections.emptyList();
            } else if (!folder.isDirectory()) {
                throw new IOException(folder.getPath() + " is not a directory");
            }

            return Arrays.stream(Objects.requireNonNull(folder.listFiles()))
                    .map(file -> new FileEntry(folder, file.getName()))
                    .collect(Collectors.toList());
        }

        @Override
        public AbstractProjectStorage.Entry createEntry(String fileName) throws IOException {
            return new FileEntry(folder, fileName);
        }

        @Override
        public void close() throws Exception {
            // Do nothing
        }
    }

    private static class FileEntry implements AbstractProjectStorage.Entry {
        private final File folder;
        private final String fileName;

        private FileEntry(File folder, String fileName) {
            this.folder = folder;
            this.fileName = fileName;
        }

        public File getFolder() {
            return folder;
        }

        public File getFile() {
            return new File(getFolder(), fileName);
        }

        @Override
        public String getFileName() {
            return fileName;
        }

        @Override
        public InputStream openRead() throws IOException {
            return new FileInputStream(getFile());
        }

        @Override
        public OutputStream openWrite() throws IOException {
            return new FileOutputStream(getFile());
        }

        @Override
        public LazySource.Loader asLazyLoader(MemorySection section) throws IOException {
            return new LazySource.FileLoader(folder, fileName, section);
        }

        @Override
        public boolean isLazyLoadingSupported() {
            return true;
        }

        @Override
        public void delete() throws IOException {
            File file = getFile();
            if (file.exists() && !file.delete()) {
                throw new IOException(fileName + " was not deleted");
            }
        }
    }

    public static class Factory implements ProjectStorageFactory {
        @Override
        public ProjectStorage createStorage(ProgressListener progressListener) {
            return new FolderProjectStorage(progressListener);
        }
    }

}
