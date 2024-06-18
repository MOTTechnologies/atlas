package com.github.manevolent.atlas.model.node;

public interface NodeEndpoint<E extends GraphNode> {

    /**
     * Gets the model-related name for this endpoint.
     * @return name.
     */
    String getName();

    /**
     * Gets the label for this endpoint.
     * @param instance the instance of this endpoint to construct a label for.
     * @return label string.
     */
    String getLabel(E instance);

    @SuppressWarnings("unchecked")
    default String getLabelUnchecked(GraphNode node) {
        return getLabel((E) node);
    }

}
