package com.github.manevolent.atlas.logic.subaru;

import com.github.manevolent.atlas.logic.TableInspector;
import ghidra.app.emulator.MemoryAccessFilter;
import ghidra.program.model.address.AddressSpace;

import javax.help.UnsupportedOperationException;
import java.nio.ByteBuffer;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;

/**
 * A class that, acting as a MemoryAccessFilter, listens to memory access events from the Ghidra emulation engine. To
 * aid in inspecting the layout of a table, the memory access pattern (order, variable size, limits in various aspects)
 * is recorded to a series of protected fields. By comparing the values, descendant classes can recognize patterns in
 * the data access and automatically discern the intended layout of the memory structure the function is accessing.
 *
 * This is critical in automatically recognizing tables in a new, never-before seen ROM binary. Furthermore, by
 * inspecting tables, we can compare the array of all tables and their execution patterns with known ROMs in order
 * to "match" a new ROM back to a ROM we already have definitions for.
 */
public abstract class SubaruDITableInspector extends MemoryAccessFilter implements TableInspector {
    protected static final int a_length = 3;
    protected static final int b_length = 5;
    protected static final int max_length = Math.max(a_length, b_length);
    protected static final List<Integer> lengths;
    static {
        lengths = new ArrayList<>();
        lengths.add(a_length);
        lengths.add(b_length);
    }

    /**
     * Making up a random table root
     */
    protected static final long root = 0xA7145000L;
    protected static final long dataRoot = root + 0x6400;
    protected static final int dataLength = max_length * max_length;
    protected static final List<Long> dataOffsets;
    static {
        dataOffsets = new ArrayList<>();
        dataOffsets.add(dataRoot);
        dataOffsets.add(dataRoot + dataLength);
        dataOffsets.add(dataRoot + (dataLength * 2));
    }

    private final SubaruDITableFunction function;

    // State tracking variables

    /**
     * The numbero f used size offsets
     */
    protected final AtomicInteger usedSizeOffsets = new AtomicInteger(0);

    /**
     * The number of used data offsets
     */
    protected final AtomicInteger usedDataOffsets = new AtomicInteger(0);

    /**
     * The order in which data was accessed in a given structure pointer, specifically when the first index was read.
     */
    protected final Set<Long> scanOrder = new LinkedHashSet<>();

    /**
     * The order in which data was accessed in a given structure pointer; when any data was read.
     */
    protected final Set<Long> readOrder = new LinkedHashSet<>();

    // More state variables
    protected final Map<Long, Long> offsets = new HashMap<>();
    protected final Map<Long, Integer> axisLengths = new HashMap<>();
    protected final Map<Long, Integer> axisDataSizes = new HashMap<>();
    protected final Map<Long, Long> dataToStruct = new HashMap<>();
    protected final Map<Integer, Long> lengthToStruct = new HashMap<>();
    protected final Map<Long, Integer> maxReadIndex = new HashMap<>();
    protected final Map<Long, Integer> reads = new HashMap<>();
    protected final Map<Long, Integer> maxReadValue = new HashMap<>();

    public SubaruDITableInspector(SubaruDITableFunction function) {
        this.function = function;
    }

    /**
     * Handle memory read events from the OS code and generate new pointers, etc. based on the access request.
     * @param addressSpace the address space being read
     * @param addr the address being read
     * @param len the length of memory being read
     * @param data the mutable data buffer
     */
    @Override
    protected void processRead(AddressSpace addressSpace, long addr, int len, byte[] data) {
        if (!addressSpace.isMemorySpace()) {
            return;
        }

        ByteBuffer buffer = ByteBuffer.wrap(data).order(function.getOS().getByteOrder());

        // Table structure access
        if (addr >= root && addr + len <= root + 16) {
            if (len == 4) {
                long dataOffset = offsets.computeIfAbsent(addr,
                        a -> dataOffsets.get(usedDataOffsets.getAndIncrement()));
                dataToStruct.put(dataOffset, addr);
                maxReadIndex.put(dataOffset, 0);
                maxReadValue.put(dataOffset, 0);
                reads.put(dataOffset, 0);
                buffer.putInt((int) (dataOffset & 0xFFFFFFFFL));
            } else if (len == 1) {
                int size = axisLengths.computeIfAbsent(addr,
                        a -> lengths.get(usedSizeOffsets.getAndIncrement()));
                lengthToStruct.put(size, addr);
                buffer.put((byte) (size & 0xFF));
            } else {
                throw new UnsupportedOperationException();
            }
        }

        for (int i = 0; i < offsets.size(); i ++) {
            long offset = dataOffsets.get(i);
            int padding = i * dataLength;
            if (addr >= offset && addr + len <= offset + dataLength) {
                int index = (int) ((addr - offset) / len);
                if (index == 0) {
                    scanOrder.add(offset);
                }

                readOrder.add(offset);

                int value;

                if (function.getDimensions() == 2) {
                    value = index;
                } else {
                    value = padding + index;
                }

                axisDataSizes.put(offset, Math.toIntExact(len));

                if (len == 1) {
                    buffer.put((byte) value);
                } else if (len == 2) {
                    buffer.putShort((short) value);
                } else if (len == 4) {
                    buffer.putInt(value);
                } else {
                    throw new UnsupportedOperationException();
                }

                Integer maxIndex = maxReadIndex.get(offset);
                index = Math.max(maxIndex, index);
                if (index > maxIndex) {
                    maxReadIndex.put(offset, index);
                }

                reads.compute(offset, (o, v) -> v + 1);

                Integer maxValue = maxReadValue.get(offset);
                value = Math.max(maxValue, value);
                if (value > maxValue) {
                    maxReadValue.put(offset, value);
                }

                break;
            }
        }
    }

    @Override
    protected void processWrite(AddressSpace addressSpace, long l, int i, byte[] bytes) {

    }

    @Override
    public SubaruDITableFunction getFunction() {
        return function;
    }

    protected void checkVariable(String variableName, int value, Set<String> missingVariables) {
        checkVariable(variableName, value, 0, missingVariables);
    }

    protected void checkVariable(String variableName, int value, int minValue, Set<String> missingVariables) {
        checkVariable(variableName, value, v -> v >= minValue, missingVariables);
    }

    protected void checkVariable(String variableName, int value, Predicate<Integer> predicate,
                                 Set<String> missingVariables) {
        if (!predicate.test(value)) {
            missingVariables.add(variableName);
        }
    }
}