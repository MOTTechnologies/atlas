package com.github.manevolent.atlas.ui.component.graph;

import com.github.manevolent.atlas.model.node.GraphNode;
import com.github.manevolent.atlas.ui.behavior.MemoryFrameListener;

import javax.swing.*;
import java.util.List;
import java.util.stream.Stream;

/**
 * An interface that types a "graph renderer", a class responsible for creating components from graph nodes and
 * rendering graphs that contain those nodes.
 */
public interface GraphRenderer extends MemoryFrameListener {

    /**
     * Gets a previously created component for a given node.
     * @param node node to find the component for.
     * @return implementation-specific component instance.
     */
    NodeComponent getComponent(GraphNode node);

    /**
     * Renders a node to a given component, returning the component created.
     * @param node node to render to a component.
     * @return implementation-specific component instance.
     */
    NodeComponent createComponent(GraphNode node);

    /**
     * Deletes a component from the graph.
     * @param component node to delete.
     */
    void deleteComponent(NodeComponent component);

    /**
     * Creates a swing render target to render the graph constructed by calls to createComponent(GraphNode), etc.
     * @return render target instance.
     */
    GraphComponent createRenderTarget();

    /**
     * Resets the graph, effectively clearing all nodes and connections, but allows for reuse of the renderer.
     */
    void reset();

    /**
     * Called to deconstruct and close this graph renderer, clearing all nodes/components from it and destroying it.
     */
    void close();

    /**
     * Gets all created components.
     * @return components.
     */
    List<NodeComponent> getNodeComponents();

    /**
     * Gets all visible components.
     * @return visible components.
     */
    default Stream<NodeComponent> getVisibleComponents() {
        return getNodeComponents().stream().filter(NodeComponent::isShowingOnScreen);
    }
}
