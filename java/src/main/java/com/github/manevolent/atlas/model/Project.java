package com.github.manevolent.atlas.model;

import com.github.manevolent.atlas.connection.ConnectionType;
import com.github.manevolent.atlas.model.node.GraphModule;
import com.github.manevolent.atlas.model.node.GraphNode;
import com.github.manevolent.atlas.model.node.NodeConnection;
import com.github.manevolent.atlas.model.storage.Ordinal;
import com.google.errorprone.annotations.Var;

import java.util.*;
import java.util.function.Consumer;
import java.util.stream.Collectors;

public class Project extends AbstractAnchored {
    private ConnectionType connectionType;

    private List<Variant> variants = new ArrayList<>();
    private List<MemorySection> sections = new ArrayList<>();
    private List<KeySet> keySets = new ArrayList<>();
    private List<Calibration> calibrations = new ArrayList<>();
    private Set<Scale> scales = new LinkedHashSet<>(); // AKA formats
    private Set<MemoryParameter> parameters = new LinkedHashSet<>();
    private List<Table> tables = new ArrayList<>();
    private List<GaugeSet> gaugeSets = new ArrayList<>();
    private GaugeSet activeGaugeSet;
    private List<GraphModule> graphModules = new ArrayList<>();
    private List<GraphNode> graphNodes = new ArrayList<>();
    private List<NodeConnection> nodeConnections = new ArrayList<>();

    public Project() {

    }

    public void setConnectionType(ConnectionType connectionType) {
        this.connectionType = connectionType;
    }

    @Ordinal(order = 10)
    public ConnectionType getConnectionType() {
        return this.connectionType;
    }

    @Ordinal(order = 90)
    public List<GraphModule> getGraphModules() {
        return graphModules;
    }

    public void setGraphModules(List<GraphModule> graphModules) {
        this.graphModules = graphModules;
    }

    public void addGraphModule(GraphModule graphModule) {
        this.graphModules.add(graphModule);
    }

    public void removeGraphModule(GraphModule graphModule) {
        new ArrayList<>(getGraphNodes()).stream()
                .filter(node -> node.getModule() == graphModule)
                .forEach(this::removeGraphNode);

        this.graphModules.remove(graphModule);
    }

    @Ordinal(order = 91)
    public List<GraphNode> getGraphNodes() {
        return graphNodes;
    }

    public List<GraphNode> getGraphNodes(GraphModule module) {
        return graphNodes.stream().filter(n -> n.getModule() == module).toList();
    }

    public void setGraphNodes(List<GraphNode> graphNodes) {
        this.graphNodes = graphNodes;
    }

    public void addGraphNode(GraphNode graphNode) {
        this.graphNodes.add(graphNode);
    }

    public void removeGraphNode(GraphNode graphNode) {
        this.graphNodes.remove(graphNode);

        this.nodeConnections.removeIf(connection ->
            connection.getSource() == graphNode || connection.getTarget() == graphNode
        );
    }

    @Ordinal(order = 92)
    public List<NodeConnection> getNodeConnections() {
        return nodeConnections;
    }

    public void setNodeConnections(List<NodeConnection> nodeConnections) {
        this.nodeConnections = nodeConnections;
    }

    public void addNodeConnection(NodeConnection nodeConnection) {
        this.nodeConnections.add(nodeConnection);
    }

    public void removeNodeConnection(NodeConnection nodeConnection) {
        this.nodeConnections.remove(nodeConnection);
    }

    public boolean hasNodeConnection(NodeConnection connection) {
        return nodeConnections.stream().anyMatch(c -> c.equals(connection));
    }

    @Ordinal(order = 20)
    public List<MemorySection> getSections() {
        return sections;
    }

    public void setSections(List<MemorySection> sections) {
        this.sections = sections;
    }

    @Ordinal(order = 70)
    public List<Table> getTables() {
        return tables;
    }

    public Table findTableByName(String name) {
        return tables.stream()
                .filter(table -> table.getName() != null && table.getName().equals(name))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException(name));
    }

    public void setTables(List<Table> tables) {
        this.tables = tables;
    }

    @Ordinal(order = 50)
    public Set<Scale> getScales() {
        return scales;
    }

    public Scale getNoneScale(DataFormat format) {
        return getScales().stream().filter(
                x -> x.getName().equals(Scale.NONE_NAME) && x.getUnit() == Unit.NONE && x.getFormat() == format
        ).findFirst().orElse(null);
    }

    public void setScales(Set<Scale> scales) {
        this.scales = scales;
    }

    public boolean hasScale(Scale scale) {
        return scales.contains(scale);
    }

    public void removeScale(Scale scale) {
        scales.remove(scale);
    }

    public void addScale(Scale scale) {
        scales.add(scale);
    }

    public boolean hasTable(Table table) {
        return tables.contains(table);
    }

    public void addTable(Table table) {
        tables.add(table);
    }

    public void removeTable(Table toDelete) {
        tables.remove(toDelete);
    }

    public boolean hasParameter(MemoryParameter parameter) {
        return parameters.contains(parameter);
    }

    public void addParameter(MemoryParameter parameter) {
        Scale scale = parameter.getScale();

        if (!scales.contains(scale)) {
            throw new IllegalArgumentException("Unknown scale(s) for parameter " + parameter.toString() + ": " +
                    parameter.getScale().toString());
        }

        parameters.add(parameter);
    }

    public void removeParameter(MemoryParameter parameter) {
        parameters.remove(parameter);
    }

    @Ordinal(order = 60)
    public Set<MemoryParameter> getParameters() {
        return parameters;
    }

    public List<MemoryParameter> getParameters(Scale scale) {
        return parameters.stream().filter(parameter -> parameter.getScale() == scale).toList();
    }

    public void setParameters(Set<MemoryParameter> parameters) {
        this.parameters = parameters;
    }

    public static Builder builder() {
        return new Builder();
    }

    public List<MemoryReference> getMemoryReferences() {
        List<MemoryReference> references = new ArrayList<>();

        getCalibrations().forEach(calibration -> {
            references.add(MemoryReference.of(calibration));
        });

        getTables().forEach(table -> {
            if (table.getData() != null) {
                references.add(MemoryReference.of(table, table.getData()));
            }

            for (Series series : table.getAllAxes()) {
                references.add(MemoryReference.of(table, series));
            }
        });

        getParameters().forEach(parameter -> {
            references.add(MemoryReference.of(parameter));
        });

        getGaugeSets().stream()
                .flatMap(set -> set.getGauges().stream())
                .forEach(gauge -> references.add(MemoryReference.of(gauge)));

        return references;
    }

    public void addSection(MemorySection section) {
        sections.add(section);
    }

    public boolean removeSection(MemorySection section) {
        return sections.remove(section);
    }

    public boolean hasSection(MemorySection section) {
        return sections.contains(section);
    }

    public MemorySection getCodeSection() {
        return getSections().stream()
                .filter(s -> s.getMemoryType() == MemoryType.CODE)
                .findFirst().orElse(null);
    }

    public void addCalibration(Calibration calibration) {
        getVariants().stream()
                .filter(v -> v.get_anchor().equals(calibration.getVariant().get_anchor()))
                .findFirst()
                .ifPresent(calibration::setVariant);

        this.calibrations.add(calibration);
    }

    public boolean removeCalibration(Calibration calibration) {
        return calibrations.remove(calibration);
    }

    public boolean hasCalibration(Calibration calibration) {
        return calibrations.contains(calibration);
    }

    @Ordinal(order = 40)
    public List<Calibration> getCalibrations() {
        return calibrations;
    }

    public void setCalibrations(List<Calibration> calibrations) {
        this.calibrations = calibrations;
    }

    @Ordinal(order = 80)
    public List<GaugeSet> getGaugeSets() {
        return this.gaugeSets;
    }

    public void setGaugeSets(List<GaugeSet> gaugeSets) {
        this.gaugeSets = gaugeSets;
    }

    @Ordinal(order = 81)
    public GaugeSet getActiveGaugeSet() {
        return activeGaugeSet;
    }

    public void setActiveGaugeSet(GaugeSet activeGaugeSet) {
        this.activeGaugeSet = activeGaugeSet;
    }

    public void addGaugeSet(GaugeSet newGaugeSet) {
        getGaugeSets().add(newGaugeSet);
    }

    public void removeGaugeSet(GaugeSet gaugeSet) {
        getGaugeSets().remove(gaugeSet);
    }

    @Ordinal(order = 30)
    public List<KeySet> getKeySets() {
        return keySets;
    }

    public void setKeySets(List<KeySet> keySets) {
        this.keySets = keySets;
    }

    public void addKeySet(KeySet keySet) {
        getKeySets().add(keySet);
    }

    public void removeKeySet(KeySet keySet) {
        getKeySets().remove(keySet);
    }

    @Ordinal(order = 5)
    public List<Variant> getVariants() {
        return variants;
    }

    public void setVariants(List<Variant> variants) {
        this.variants = variants;
    }

    public void addVariant(Variant variant) {
        Variant existing = getVariants().stream()
                .filter(v -> v.get_anchor().equals(variant.get_anchor()))
                .findFirst()
                .orElse(null);

        if (existing == null) {
            variants.add(variant);
        }
    }

    public void removeVariant(Variant variant) {
        getVariants().remove(variant);
    }

    public void setup() {
        getSections().forEach(x -> x.setup(this));
        getTables().forEach(x -> x.setup(this));
    }

    public KeySet getActiveKeySet() {
        return keySets.stream().max(Comparator.comparing(KeySet::isActive)).orElse(null);
    }

    public Project asConfidentialProject() {
        Project confidentialProject = new Project();
        confidentialProject.set_anchor(get_anchor());
        confidentialProject.setKeySets(Secured.asConfidential(getKeySets()));
        confidentialProject.setCalibrations(Secured.asConfidential(getCalibrations()));
        confidentialProject.setScales(Secured.asConfidential(getScales()));
        confidentialProject.setSections(Secured.asConfidential(getSections()));
        confidentialProject.setGaugeSets(Secured.asConfidential(getGaugeSets()));
        confidentialProject.setParameters(Secured.asConfidential(getParameters()));
        confidentialProject.setTables(Secured.asConfidential(getTables()));
        confidentialProject.setGraphModules(Secured.asConfidential(getGraphModules()));
        confidentialProject.setGraphNodes(Secured.asConfidential(getGraphNodes()));
        confidentialProject.setNodeConnections(Secured.asConfidential(getNodeConnections()));
        confidentialProject.setVariants(Secured.asConfidential(getVariants()));
        return confidentialProject;
    }

    public Project asPublicProject() {
        Project publicProject = new Project();
        publicProject.set_anchor(get_anchor());

        publicProject.setConnectionType(getConnectionType());
        publicProject.setActiveGaugeSet(getActiveGaugeSet());

        publicProject.setKeySets(Secured.asPublic(getKeySets()));
        publicProject.setCalibrations(Secured.asPublic(getCalibrations()));
        publicProject.setScales(Secured.asPublic(getScales()));
        publicProject.setSections(Secured.asPublic(getSections()));
        publicProject.setGaugeSets(Secured.asPublic(getGaugeSets()));
        publicProject.setParameters(Secured.asPublic(getParameters()));
        publicProject.setTables(Secured.asPublic(getTables()));
        publicProject.setGraphModules(Secured.asPublic(getGraphModules()));
        publicProject.setGraphNodes(Secured.asPublic(getGraphNodes()));
        publicProject.setNodeConnections(Secured.asPublic(getNodeConnections()));
        publicProject.setVariants(Secured.asPublic(getVariants()));

        return publicProject;
    }

    public void merge(Project... projects) {
        for (Project project : projects) {
            project.getVariants().forEach(this::addVariant);
            project.getKeySets().forEach(this::addKeySet);
            project.getCalibrations().forEach(cal -> {
                cal.setSection(getCodeSection());
                this.addCalibration(cal);
            });
            project.getScales().forEach(this::addScale);
            project.getSections().forEach(this::addSection);
            project.getGaugeSets().forEach(this::addGaugeSet);
            project.getParameters().forEach(this::addParameter);
            project.getTables().forEach(this::addTable);
            project.getGraphModules().forEach(this::addGraphModule);
            project.getGraphNodes().forEach(this::addGraphNode);
            project.getNodeConnections().forEach(this::addNodeConnection);
        }
    }

    public static class Builder {
        private final Project project = new Project();

        public Builder() {
            project.setTables(new ArrayList<>());
            project.setSections(new ArrayList<>());
            project.setScales(new LinkedHashSet<>());
            project.setParameters(new LinkedHashSet<>());
            project.setCalibrations(new ArrayList<>());
            project.setGaugeSets(new ArrayList<>());
            project.setGraphNodes(new ArrayList<>());
            project.setVariants(new ArrayList<>());
        }

        public Builder withScales(Scale.Builder... scales) {
            project.scales.addAll(Arrays.stream(scales).map(Scale.Builder::build).toList());
            return this;
        }

        public Builder withScales(Scale... scales) {
            project.scales.addAll(Arrays.asList(scales));
            return this;
        }

        public Builder withTables(Table... tables) {
            Arrays.stream(tables).forEach(this::withTable);
            return this;
        }

        public Builder withTables(Table.Builder... builders) {
            Arrays.stream(builders).forEach(this::withTable);
            return this;
        }

        public Builder withFlashMethod(ConnectionType connectionType) {
            this.project.setConnectionType(connectionType);
            return this;
        }

        public Builder withTable(Table table) {
            // Verify scales are registered
            Set<Scale> unknownScales = new HashSet<>(table.getAxes().keySet().stream()
                    .map(table::getSeries)
                    .map(Series::getScale)
                    .filter(scale -> !this.project.scales.contains(scale))
                    .toList());

            if (!this.project.scales.contains(table.getData().getScale())) {
                unknownScales.add(table.getData().getScale());
            }

            if (!unknownScales.isEmpty()) {
                throw new IllegalArgumentException("Unknown scale(s) for table "
                        + table.getName() + ": " +
                        unknownScales.stream().map(Scale::toString)
                                .collect(Collectors.joining(", "))
                );
            }

            project.getTables().add(table);
            return this;
        }

        public Builder withTable(Table.Builder table) {
            return withTable(table.build());
        }

        public Builder withSections(MemorySection... sections) {
            project.getSections().addAll(Arrays.asList(sections));
            return this;
        }

        public Builder withSection(MemorySection section) {
            project.getSections().add(section);
            return this;
        }

        public Builder withSection(MemorySection.Builder section) {
            return withSection(section.build());
        }

        public Builder withParameter(MemoryParameter parameter) {
            project.addParameter(parameter);
            return this;
        }

        public Builder withParameter(MemoryParameter.Builder parameter) {
            return withParameter(parameter.build());
        }

        public Builder withCalibration(Calibration calibration) {
            project.addCalibration(calibration);
            return this;
        }

        public Builder withVariant(Variant variant) {
            project.addVariant(variant);
            return this;
        }

        public Project build() {
            project.setup();
            return project;
        }
    }
}
