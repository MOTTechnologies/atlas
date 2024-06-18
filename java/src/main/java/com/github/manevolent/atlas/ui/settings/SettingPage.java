package com.github.manevolent.atlas.ui.settings;

import com.github.manevolent.atlas.ui.settings.field.FieldChangeListener;
import com.github.manevolent.atlas.ui.settings.validation.ValidationState;
import org.kordamp.ikonli.Ikon;

import javax.swing.*;

/**
 * An interface that describes a single setting page (or setting tab) in a settings dialog.
 */
public interface SettingPage {

    /**
     * Gets the human-readable name for this setting page. Used by the settings dialog during
     * layout to determine the name of tabs and headers for the setting page.
     * @return name.
     */
    String getName();

    /**
     * Gets the icon for the setting page.
     * @return icon.
     */
    Ikon getIcon();

    /**
     * Gets the content shown when this setting page is selected.
     * @return content component.
     */
    JComponent getContent();

    /**
     * Called by the settings dialog when the changed values on this page should be applied.
     * @return true if application was successful, false if application failed and the dialog should abort closing.
     */
    boolean apply();

    /**
     * Called by the settings dialog when the values on this page should be validated.
     * @return the validation state of this setting page.
     */
    default ValidationState validate() {
        ValidationState state = new ValidationState();
        validate(state);
        return state;
    }

    /**
     * Called by the settings dialog when the values on this page should be validated.
     * @param state the validation state object to modify when reporting the validation state to the caller.
     */
    default void validate(ValidationState state) {

    }

    /**
     * Determines if the setting dialog should automatically wrap the content of this setting page in a scroll pane.
     * @return true if a scroll pane is needed (default), false otherwise.
     */
    default boolean isScrollNeeded() {
        return true;
    }

    /**
     * Determines if this setting page has un-applied changes to the values on the page.
     * @return true if the page is dirty, false otherwise.
     */
    boolean isDirty();

    /**
     * Called when this page should be focused.
     */
    default void focus() {

    }

    /**
     * Creates a new save dialog with this setting page as its accessory panel.
     * @return save dialog instance.
     */
    default JFileChooser newFileChooser() {
        JFileChooser chooser = new JFileChooser();
        chooser.setAccessory(getContent());
        return chooser;
    }

    void addChangeListener(FieldChangeListener listener);

    void removeChangeListener(FieldChangeListener listener);

}
