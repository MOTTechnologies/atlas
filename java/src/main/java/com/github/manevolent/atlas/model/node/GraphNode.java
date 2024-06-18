package com.github.manevolent.atlas.model.node;

import com.github.manevolent.atlas.model.Anchored;
import org.kordamp.ikonli.Ikon;

import javax.swing.*;
import java.awt.*;
import java.util.List;

public interface GraphNode extends Anchored {

    /**
     * Gets the module this node exists on.
     * @return module.
     */
    GraphModule getModule();

    /**
     * Sets the module this node exists on.
     * @param module module
     */
    void setModule(GraphModule module);

    /**
     * Gets the X coordinate for this node in screen space.
     * @return x coordinate.
     */
    float getX();

    /**
     * Sets the X coordinate for this node in screen space.
     * @param x x coordinate.
     */
    void setX(float x);

    /**
     * Gets the Y coordinate for this node in screen space.
     * @return y coordinate.
     */
    float getY();

    /**
     * Sets the Y coordinate for this node in screen space.
     * @param y y coordinate.
     */
    void setY(float y);

    /**
     * Gets the icon used for this node in the editor.
     * @return Iconli Ikon instance.
     */
    Ikon getIcon();

    /**
     * Gets the represented label for this node.
     * @return human-readable label.
     */
    String getLabel();

    /**
     * Gets the color for this node's label.
     * @return label color.
     */
    Color getLabelColor();

    /**
     * Gets the available inputs for this node.
     *
     * @return inputs
     */
    List<? extends NodeInput<?>> getInputs();

    /**
     * Gets the available outputs for this node.
     * @return outputs
     */
    List<? extends NodeOutput<?>> getOutputs();

    /**
     * Gets an output from the given stored name.
     * @param name name stored in configuration.
     * @return node output instance.
     */
    NodeOutput<?> getOutput(String name);

    /**
     * Gets an input from the given stored name.
     * @param name name stored in configuration.
     * @return node input instance.
     */
    NodeInput<?> getInput(String name);

    /**
     * Creates a new NodeConnection instance for this node
     * @param mine my endpoint to add a connection from.
     * @param them the graph node with an endpoint to connect to.
     * @param theirs their endpoint to connect to.
     */
    NodeConnection createConnection(NodeEndpoint<?> mine, GraphNode them, NodeEndpoint<?> theirs);

    /**
     * Creates a setting page for this component to control the node's specific settings, or null if no settings
     * are available to be changed.
     * @return JComponent instance for this node for settings.
     */
    default JComponent getSettingComponent() {
        return null;
    }

    /**
     * Called when this node sends or receives a connection.
     * @param connection connection instance.
     */
    default void onConnected(NodeConnection connection) {

    }
}
