package com.github.manevolent.atlas.ui.component;

import com.github.manevolent.atlas.ui.component.table.TableDefinitionEditor;

import java.awt.*;

public abstract class TableDefinitionEditorComponent<T extends Component>
        extends AtlasComponent<T, TableDefinitionEditor> {
    protected TableDefinitionEditorComponent(TableDefinitionEditor editor) {
        super(editor);
    }
}
