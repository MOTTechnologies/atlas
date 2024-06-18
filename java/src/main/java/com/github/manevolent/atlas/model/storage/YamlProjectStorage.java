package com.github.manevolent.atlas.model.storage;

import com.github.manevolent.atlas.connection.ConnectionType;

import com.github.manevolent.atlas.model.*;
import com.github.manevolent.atlas.model.crypto.MemoryEncryptionType;

import com.github.manevolent.atlas.model.node.*;
import com.github.manevolent.atlas.model.uds.SecurityAccessProperty;
import com.github.manevolent.atlas.ui.behavior.ProgressListener;

import org.checkerframework.checker.units.qual.A;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;
import org.yaml.snakeyaml.inspector.TagInspector;
import org.yaml.snakeyaml.introspector.BeanAccess;
import org.yaml.snakeyaml.introspector.Property;
import org.yaml.snakeyaml.introspector.PropertyUtils;
import org.yaml.snakeyaml.nodes.*;
import org.yaml.snakeyaml.representer.Representer;
import org.yaml.snakeyaml.serializer.NumberAnchorGenerator;

import java.io.*;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.*;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public abstract class YamlProjectStorage extends AbstractProjectStorage {
    private static final String fileNameFormat = "%s.%s"; // i.e. to produce 'project.yaml'
    private static final String extension = "yaml";
    private static final String projectFileName = String.format(fileNameFormat, "project", extension);

    private static final Charset charset = StandardCharsets.UTF_16;

    private static final Set<String> acceptableClassNames = Collections.unmodifiableSet(Stream.of(
            Project.class, Scale.class, ScalingOperation.class,
            Series.class, Table.class, Unit.class, UnitClass.class,
            Vehicle.class, Precision.class, MemorySection.class, MemoryParameter.class,
            MemoryByteOrder.class, MemoryAddress.class, DataFormat.class,
            Axis.class, ArithmeticOperation.class, MemoryEncryptionType.class, KeyProperty.class,
            Color.class, SecurityAccessProperty.class, ConnectionType.class,
            Calibration.class, UUID.class, Gauge.class, GaugeSet.class, GaugeDisplayType.class,
            GraphNode.class, NodeEndpoint.class, NodeInput.class, NodeOutput.class, GraphNodeType.class,
            NodeConnection.class, TableNode.class, TableNode.Input.class, ParameterNode.class, DocumentationNode.class,
            GraphModule.class, OSType.class, AddressProperty.class
    ).map(Class::getName).collect(Collectors.toSet()));

    public YamlProjectStorage(ProgressListener listener) {
        super(listener);
    }

    private Entry getPublicProjectFile(Container container) throws IOException {
        return container.getEntry(projectFileName);
    }

    private Entry createPublicProjectFile(Container container) throws IOException {
        return container.createEntry(projectFileName);
    }

    private Entry getConfidentialProjectFile(Container container) throws IOException {
        return container.getEntry("confidential_" + projectFileName);
    }

    private Entry createConfidentialProjectFile(Container container) throws IOException {
        return container.createEntry("confidential_" + projectFileName);
    }

    private Yaml getYaml(AtomicBoolean allowConfidential) {
        TagInspector taginspector = tag -> acceptableClassNames.contains(tag.getClassName());

        LoaderOptions loaderOptions = new LoaderOptions();
        loaderOptions.setMaxAliasesForCollections(102400);
        loaderOptions.setNestingDepthLimit(1024);
        loaderOptions.setTagInspector(taginspector);

        Constructor constructor = new Constructor(loaderOptions) {
            @Override
            protected Object newInstance(Class<?> ancestor, Node node, boolean tryDefault) {
                Object instance = super.newInstance(ancestor, node, tryDefault);
                if (instance instanceof Anchored anchored) {
                    anchored.set_anchor(node.getAnchor());
                }
                return instance;
            }
        };

        DumperOptions dumperOptions = new DumperOptions();
        dumperOptions.setAllowUnicode(true);
        dumperOptions.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        dumperOptions.setSplitLines(false);
        dumperOptions.setAnchorGenerator(new Generator());
        dumperOptions.setLineBreak(DumperOptions.LineBreak.WIN);
        dumperOptions.setTimeZone(TimeZone.getTimeZone("UTC"));

        Representer representer = new Representer(dumperOptions) {
            @Override
            protected MappingNode representJavaBean(Set<Property> properties, Object javaBean) {
                MappingNode node = super.representJavaBean(properties, javaBean);

                if (javaBean instanceof Anchored anchored) {
                    node.setAnchor(anchored.get_anchor());

                    // Remove the automatically generated ("_anchor")
                    node.getValue().removeIf(
                            x -> x.getKeyNode() instanceof ScalarNode scalar
                            && scalar.getValue().equals("_anchor")
                    );
                }

                if (javaBean instanceof Secured secured) {
                    if (secured.isConfidential() && !allowConfidential.get()) {
                        throw new SecurityException("Cannot save secure bean " + javaBean +
                                " to a non-confidential project YAML");
                    }
                }

                return node;
            }
        };

        PropertyUtils propertyUtils = new PropertyUtils() {
            @Override
            protected Set<Property> createPropertySet(Class<?> type, BeanAccess bAccess) {
                return getPropertiesMap(type, bAccess).values()
                        .stream()
                        .sorted(Comparator.comparingInt(property -> {
                            Ordinal ordinal = property.getAnnotation(Ordinal.class);
                            if (ordinal != null) {
                                return ordinal.order();
                            } else {
                                return Integer.MAX_VALUE;
                            }
                        }))
                        .filter(prop -> prop.isReadable() && (isAllowReadOnlyProperties() || prop.isWritable()))
                        .collect(Collectors.toCollection(LinkedHashSet::new));
            }
        };
        propertyUtils.setSkipMissingProperties(true);
        representer.setPropertyUtils(propertyUtils);

        return new Yaml(constructor, representer, dumperOptions);
    }

    @Override
    protected Project readProject(Container container) throws IOException {
        Yaml yaml = getYaml(new AtomicBoolean(true));

        Entry projectFileEntry = getPublicProjectFile(container);
        Project publicProject = projectFileEntry.withRead(inputStream -> {
            try (Reader reader = new InputStreamReader(inputStream, charset)) {
                return yaml.load(reader);
            }
        });

        Entry confidentialFileEntry = getConfidentialProjectFile(container);
        if (confidentialFileEntry != null) {
            Project confidentialProject = confidentialFileEntry.withRead(inputStream -> {
                try (Reader reader = new InputStreamReader(inputStream, charset)) {
                    return yaml.load(reader);
                }
            });

            publicProject.merge(confidentialProject);
        }

        return publicProject;
    }

    @Override
    protected void writeProject(Project project, Container container) throws IOException {
        AtomicBoolean allowConfidential = new AtomicBoolean();
        Yaml yaml = getYaml(allowConfidential);

        allowConfidential.set(false);
        String publicString = yaml.dump(project.asPublicProject());

        allowConfidential.set(true);
        String confidentialString = yaml.dump(project.asConfidentialProject());

        allowConfidential.set(false);

        Entry projectFileEntry = createPublicProjectFile(container);
        projectFileEntry.withWrite(os -> {
            try (Writer writer = new OutputStreamWriter(os, charset)) {
                writer.write(publicString);
            }
        });

        if (canWriteConfidentialData()) {
            Entry confidentialFileEntry = createConfidentialProjectFile(container);
            confidentialFileEntry.withWrite(os -> {
                try (Writer writer = new OutputStreamWriter(os, charset)) {
                    writer.write(confidentialString);
                }
            });
        }
    }

    public static class Factory implements ProjectStorageFactory {
        @Override
        public ProjectStorage createStorage(ProgressListener progressListener) {
            return new ZipProjectStorage(progressListener);
        }
    }

    public static class Generator extends NumberAnchorGenerator {
        public Generator() {
            super(0);
        }

        @Override
        public String nextAnchor(Node node) {
            String anchor = node.getAnchor();

            if (anchor == null) {
                return super.nextAnchor(node);
            }

            return anchor;
        }
    }

}
