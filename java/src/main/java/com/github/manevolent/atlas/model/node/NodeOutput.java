package com.github.manevolent.atlas.model.node;

import java.awt.*;

public interface NodeOutput<E extends GraphNode> extends NodeEndpoint<E> {
    Color getColor(E instance);


    @SuppressWarnings("unchecked")
    default Color getColorUnchecked(GraphNode node) {
        return getColor((E) node);
    }
}
