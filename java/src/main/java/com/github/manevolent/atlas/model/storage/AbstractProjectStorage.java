package com.github.manevolent.atlas.model.storage;

import com.github.manevolent.atlas.checked.CheckedConsumer;
import com.github.manevolent.atlas.checked.CheckedFunction;
import com.github.manevolent.atlas.logging.Log;
import com.github.manevolent.atlas.model.*;
import com.github.manevolent.atlas.model.source.LazySource;
import com.github.manevolent.atlas.ui.behavior.ProgressListener;
import com.google.common.io.CharSource;
import net.lingala.zip4j.ZipFile;
import net.lingala.zip4j.model.FileHeader;

import net.lingala.zip4j.model.ZipParameters;

import org.yaml.snakeyaml.Yaml;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

import java.util.logging.Level;

public abstract class AbstractProjectStorage implements ProjectStorage {
    private final ProgressListener listener;

    protected AbstractProjectStorage(ProgressListener listener) {
        this.listener = listener;
    }

    protected abstract boolean canWriteConfidentialData();

    protected abstract Project readProject(Container container) throws IOException;

    protected abstract void writeProject(Project project, Container container) throws IOException;

    protected abstract Container openContainerRead(File file) throws IOException;

    protected abstract Container openContainerWrite(File file) throws IOException;

    protected Project withContainerRead(File file, CheckedFunction<Container, Project, IOException> function)
            throws IOException {
        try (Container container = openContainerRead(file)) {
            return function.applyChecked(container);
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    protected void withContainerWrite(File file, CheckedConsumer<Container, IOException> consumer)
            throws IOException {
        try (Container container = openContainerWrite(file)) {
            consumer.acceptChecked(container);
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    @Override
    public Project load(File file) throws IOException {
        return withContainerRead(file, container -> {
            Map<UUID, Entry> sections = new LinkedHashMap<>();

            for (Entry entry : container.getEntries()) {
                String fileName = entry.getFileName();

                if (fileName.endsWith(".bin")) {
                    String uuidString = fileName.replaceFirst("\\.bin$", "")
                            .replaceFirst("^confidential_", ""); // Confidential files start with "confidential."

                    try {
                        UUID uuid = UUID.fromString(uuidString);
                        sections.put(uuid, entry);
                    } catch (Exception ex) {
                        Log.ui().log(Level.WARNING, "Problem opening calibration binary \"" + fileName + "\"", ex);
                    }
                }
            }

            Project project = readProject(container);

            if (project.getCalibrations() == null) {
                project.setCalibrations(new ArrayList<>());
            }

            for (Calibration calibration : project.getCalibrations()) {
                MemorySection section = calibration.getSection();
                if (section == null) {
                    continue;
                }

                Entry sectionEntry = sections.get(calibration.getUuid());
                if (sectionEntry.isLazyLoadingSupported()) {
                    calibration.updateSource(new LazySource(sectionEntry.asLazyLoader(section)));
                } else {
                    calibration.updateSource(sectionEntry.withRead(InputStream::readAllBytes));
                }
            }

            project.setup();

            for (DataFormat format : DataFormat.values()) {
                if (project.getScales().stream().noneMatch(x ->
                        x.getName().equals(Scale.NONE_NAME) && x.getFormat() == format)) {
                    project.addScale(Scale.getNone(format));
                }
            }

            return project;
        });
    }

    @Override
    public void save(Project project, File file) throws IOException {
        withContainerWrite(file, container -> {
            Yaml yaml = new Yaml();

            // Save calibrations
            List<String> writtenCalibrations = new ArrayList<>();
            for (Calibration calibration : project.getCalibrations()) {
                if (!calibration.hasData()) {
                    continue;
                }

                String fileName = calibration.getUuid().toString() + ".bin";

                if (calibration.isConfidential()) {
                    if (!canWriteConfidentialData()) {
                        continue;
                    }

                    fileName = String.format("confidential_%s", fileName);
                }

                Entry existingFile = container.getEntry(fileName);
                writtenCalibrations.add(fileName);

                MemorySource source = calibration.getSource();
                if (source instanceof LazySource lazySource && !lazySource.isDirty() && existingFile != null) {
                    // Don't modify the existing calibration data; it isn't dirty
                    continue;
                } else if (existingFile == null) {
                    existingFile = container.createEntry(fileName);
                }

                existingFile.withWrite(os -> os.write(source.readFully()));
            }

            for (Entry entry : container.getEntries()) {
                if (!entry.getFileName().endsWith(".bin")) {
                    continue;
                } else if (writtenCalibrations.stream().anyMatch(fileName -> fileName.equals(entry.getFileName()))) {
                    continue;
                }

                entry.delete();
            }

            writeProject(project, container);
        });

        project.getCalibrations().stream()
                .map(Calibration::getSource)
                .filter(source -> source instanceof LazySource)
                .map(source -> (LazySource) source)
                .forEach(source -> source.setDirty(false));
    }

    public interface Container extends AutoCloseable {

        File getFile();

        Collection<Entry> getEntries() throws IOException;

        default Entry getEntry(String fileName) throws IOException {
            return getEntries().stream().filter(x -> x.getFileName().equals(fileName)).findFirst().orElse(null);
        }

        Entry createEntry(String fileName) throws IOException;

    }

    public interface Entry {

        String getFileName();

        default <T> T withRead(CheckedFunction<InputStream, T, IOException> function) throws IOException {
            try (InputStream inputStream = openRead()) {
                return function.apply(inputStream);
            }
        }

        InputStream openRead() throws IOException;

        default void withWrite(CheckedConsumer<OutputStream, IOException> consumer) throws IOException {
            try (OutputStream outputStream = openWrite()) {
                consumer.accept(outputStream);
            }
        }

        OutputStream openWrite() throws IOException;

        LazySource.Loader asLazyLoader(MemorySection section) throws IOException;

        boolean isLazyLoadingSupported();

        void delete() throws IOException;

    }
}
