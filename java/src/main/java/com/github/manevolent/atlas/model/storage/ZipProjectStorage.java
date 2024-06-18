package com.github.manevolent.atlas.model.storage;

import com.github.manevolent.atlas.model.MemorySection;
import com.github.manevolent.atlas.model.source.LazySource;
import com.github.manevolent.atlas.ui.behavior.ProgressListener;
import net.lingala.zip4j.ZipFile;
import net.lingala.zip4j.model.FileHeader;
import net.lingala.zip4j.model.ZipParameters;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.io.*;
import java.util.Collection;
import java.util.stream.Collectors;

public class ZipProjectStorage extends YamlProjectStorage {
    public ZipProjectStorage(ProgressListener listener) {
        super(listener);
    }

    @Override
    protected boolean canWriteConfidentialData() {
        return false;
    }

    @Override
    protected Container openContainerRead(File file) throws IOException {
        return new ZipContainer(file, new ZipFile(file));
    }

    @Override
    protected Container openContainerWrite(File file) throws IOException {
        return new ZipContainer(file, new ZipFile(file));
    }

    @Override
    public JFileChooser createFileChooser() {
        JFileChooser fileChooser = new JFileChooser();
        FileNameExtensionFilter def = new FileNameExtensionFilter("Atlas project files", "atlas");
        fileChooser.addChoosableFileFilter(def);
        fileChooser.setFileFilter(def);
        return fileChooser;
    }

    private static class ZipContainer implements AbstractProjectStorage.Container {
        private final File file;
        private final ZipFile zipFile;

        private ZipContainer(File file, ZipFile zipFile) {
            this.file = file;
            this.zipFile = zipFile;
        }

        @Override
        public File getFile() {
            return file;
        }

        @Override
        public Collection<Entry> getEntries() throws IOException {
            return zipFile.getFileHeaders().stream()
                    .map(header -> new ZipEntry(zipFile, header))
                    .collect(Collectors.toList());
        }

        @Override
        public Entry createEntry(String fileName) throws IOException {
            Entry entry = getEntry(fileName);

            if (entry == null) {
                entry = new ZipEntry(zipFile, fileName);
            }

            return entry;
        }

        @Override
        public void close() throws Exception {
            zipFile.close();
        }
    }

    private static class ZipEntry implements AbstractProjectStorage.Entry {
        private final ZipFile file;
        private final String fileNameInZip;
        private final FileHeader header;

        private ZipEntry(ZipFile file, FileHeader header) {
            this.file = file;
            this.fileNameInZip = header.getFileName();
            this.header = header;
        }

        private ZipEntry(ZipFile file, String fileNameInZip) {
            this.file = file;
            this.fileNameInZip = fileNameInZip;
            this.header = null;
        }

        public ZipParameters getZipParameters() {
            ZipParameters parameters = new ZipParameters();
            parameters.setFileNameInZip(fileNameInZip);
            return parameters;
        }

        @Override
        public String getFileName() {
            return header.getFileName();
        }

        @Override
        public InputStream openRead() throws IOException {
            if (header != null) {
                return file.getInputStream(header);
            } else {
                throw new FileNotFoundException(fileNameInZip);
            }
        }

        @Override
        public OutputStream openWrite() throws IOException {
            return new ZipOutputStream(this);
        }

        @Override
        public LazySource.Loader asLazyLoader(MemorySection section) throws IOException {
            if (header != null) {
                return new LazySource.ZipLoader(file.getFile(), header, section);
            } else {
                throw new FileNotFoundException(fileNameInZip);
            }
        }

        @Override
        public boolean isLazyLoadingSupported() {
            return true;
        }

        @Override
        public void delete() throws IOException {
            if (header != null) {
                file.removeFile(header);
            } else {
                throw new FileNotFoundException(fileNameInZip);
            }
        }
    }

    private static class ZipOutputStream extends OutputStream {
        private final ZipEntry entry;
        private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        private ZipOutputStream(ZipEntry entry) {
            this.entry = entry;
        }

        @Override
        public void write(int b) throws IOException {
            buffer.write(b);
        }

        @Override
        public void close() throws IOException {
            entry.file.addStream(new ByteArrayInputStream(buffer.toByteArray()), entry.getZipParameters());
            super.close();
        }
    }

    public static class Factory implements ProjectStorageFactory {
        @Override
        public ProjectStorage createStorage(ProgressListener progressListener) {
            return new ZipProjectStorage(progressListener);
        }
    }
}
