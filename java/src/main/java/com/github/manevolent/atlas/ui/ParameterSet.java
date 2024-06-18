package com.github.manevolent.atlas.ui;

import com.github.manevolent.atlas.model.MemoryParameter;

import java.util.*;

public class ParameterSet {
    private final LinkedHashSet<MemoryParameter> set = new LinkedHashSet<>();
    private final Object lock = new Object();

    public ParameterSet() {

    }

    public Set<MemoryParameter> getAll() {
        return set;
    }

    public boolean isEmpty() {
        return set.isEmpty();
    }

    public int size() {
        return set.size();
    }

    public boolean contains(MemoryParameter search) {
        return set.contains(search);
    }

    public int indexOf(MemoryParameter parameter) {
        return toList().indexOf(parameter);
    }

    public List<MemoryParameter> toList() {
        synchronized (set) {
            return new ArrayList<>(set);
        }
    }

    public void moveUp(MemoryParameter parameter) {
        synchronized (lock) {
            List<MemoryParameter> copy = toList();
            int index = copy.indexOf(parameter);
            if (index <= 0) {
                return;
            }

            copy.remove(parameter);
            copy.add(index - 1, parameter);

            reset(copy);
        }
    }

    public void moveDown(MemoryParameter parameter) {
        synchronized (lock) {
            List<MemoryParameter> copy = toList();
            int index = copy.indexOf(parameter);
            if (index >= copy.size() - 1) {
                return;
            }

            copy.remove(parameter);
            copy.add(index + 1, parameter);

            reset(copy);
        }
    }

    public void add(MemoryParameter parameter) {
        synchronized (lock) {
            set.add(parameter);
        }
    }

    public void remove(MemoryParameter parameter) {
        synchronized (lock) {
            set.remove(parameter);
        }
    }

    public void clear() {
        synchronized (lock) {
            set.clear();
        }
    }

    public void reset(Collection<MemoryParameter> set) {
        synchronized (lock) {
            clear();
            this.set.addAll(set);
        }
    }
}
