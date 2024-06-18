package com.github.manevolent.atlas.ui.behavior;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

public abstract class History<T extends Action> {
    private final List<T> actions = new ArrayList<>();
    private int maximumActions = 20;
    private int position = -1;

    private List<HistoryListener<T>> historyListeners = new ArrayList<>();

    private boolean remembering = true;

    public int getMaximumActions() {
        return maximumActions;
    }

    public void setMaximumActions(int maximumActions) {
        this.maximumActions = maximumActions;
    }

    public boolean isRemembering() {
        return remembering;
    }

    public void addListener(HistoryListener<T> listener) {
        this.historyListeners.add(listener);
    }

    public void removeListener(HistoryListener<T> listener) {
        this.historyListeners.remove(listener);
    }

    protected void fireListeners(Consumer<HistoryListener<T>> consumer) {
        this.historyListeners.forEach(consumer);
    }

    public void remember(T action) {
        if (!remembering) {
            return;
        }

        // Forget anything after the current position
        while (!actions.isEmpty() && position >= 0 && actions.size() - position > 0) {
            actions.removeLast();
        }
        int index = Math.max(0, Math.min(position, actions.size()));
        actions.add(index, action);
        while (actions.size() > getMaximumActions()) {
            actions.removeFirst();
        }
        position = actions.size();

        fireListeners(l -> l.onRemembered(action));
    }

    public boolean canUndo() {
        return !actions.isEmpty() && position > 0;
    }

    public boolean canRedo() {
        return !actions.isEmpty() && actions.size() - position >= 1;
    }

    public void undo() {
        if (!canUndo()) {
            throw new IllegalStateException();
        }

        // Pop one
        boolean success = false;
        while (!success && canUndo()) {
            T action = actions.get(position - 1);
            boolean lastRememberingState = remembering;
            remembering = false;
            try {
                fireListeners(l -> l.onUndoStarted(action));
                success = action.undo();
            } finally {
                fireListeners(l -> l.onUndoCompleted(action));
                remembering = lastRememberingState;
            }
            position--;
        }

        position = Math.max(position, -1);
    }

    public void redo() {
        if (!canRedo()) {
            throw new IllegalStateException();
        }

        // Push forward one
        boolean success = false;
        while (!success && canRedo()) {
            T action = actions.get(position);
            boolean lastRememberingState = remembering;
            remembering = false;
            try {
                fireListeners(l -> l.onRedoStarted(action));
                success = action.redo();
            } finally {
                fireListeners(l -> l.onRedoCompleted(action));
                remembering = lastRememberingState;
            }
            position++;
        }

        position = Math.min(position, actions.size());
    }
}
