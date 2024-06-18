package com.github.manevolent.atlas.ui.component.toolbar;

import com.github.manevolent.atlas.model.Variant;
import org.kordamp.ikonli.fontawesome5.FontAwesomeSolid;

import javax.swing.*;

import java.util.List;

import static com.github.manevolent.atlas.ui.util.Inputs.showOptionDialog;

/**
 * A reusable toolbar that typically would be placed above a variant list for a facet of a project that has variance,
 * like Tables and MemoryParameters.
 * @param <T> type of editor this toolbar is embedded in.
 */
public abstract class VariantToolbar<T> extends Toolbar<T> {

    protected VariantToolbar(T editor) {
        super(editor);
    }

    @Override
    protected void initComponent(JToolBar toolbar) {
        toolbar.add(makeSmallButton(FontAwesomeSolid.PLUS, "add", "Add variant", e -> {
            List<Variant> options = getUnsupportedVariants();
            Variant variant = showOptionDialog(getEditor(), "Add Variant", "Select a variant to add:", options);
            if (variant == null) {
                return;
            }

            addVariant(variant);
        }));

        toolbar.add(makeSmallButton(FontAwesomeSolid.TRASH, "delete", "Delete variant", e -> {
            Variant variant = getCurrentVariant();
            if (variant == null || !getSupportedVariants().contains(variant)) {
                return;
            }

            deleteVariant(variant);
        }));
    }

    /**
     * Gets, or calculates, the unsupported variants of the object the editor is operating on (i.e. Table). This is used
     * to decide what variants to display to the user when they are choosing one to add support for.
     * @return list of unsupported variants.
     */
    protected List<Variant> getUnsupportedVariants() {
        List<Variant> supported = getSupportedVariants();
        return getProject().getVariants().stream().filter(x -> !supported.contains(x)).toList();
    }

    /**
     * Gets the variants supported by the object the editor is operating on (i.e. Table)
     * @return list of supported variants.
     */
    protected abstract List<Variant> getSupportedVariants();

    /**
     * Gets the variant currently selected in the parent editor.
     * @return selected/active variant.
     */
    protected abstract Variant getCurrentVariant();

    /**
     * Implemented by the editor to receive the add supported variant event.
     * @param variant project-defined variant to add support for.
     */
    protected abstract void addVariant(Variant variant);


    /**
     * Implemented by the editor to receive the remove supported variant event.
     * @param variant project-defined variant to remove support for.
     */
    protected abstract void deleteVariant(Variant variant);

}
