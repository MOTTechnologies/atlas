package com.github.manevolent.atlas.ui.component;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.JTableHeader;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableColumn;
import java.awt.Component;
import java.awt.FontMetrics;
 
public class ColumnsAutoSizer {
    private static final int MAXIMUM_ROWS = 100;
 
    public static void sizeColumnsToFit(JTable table) {
        sizeColumnsToFit(table, 5);
    }
 
    public static void sizeColumnsToFit(JTable table, int columnMargin) {
        JTableHeader tableHeader = table.getTableHeader();
 
        if(tableHeader == null) {
            // can't auto size a table without a header
            return;
        }

        if (table.getRowCount() > MAXIMUM_ROWS) {
            return;
        }
 
        FontMetrics headerFontMetrics = tableHeader.getFontMetrics(tableHeader.getFont());
 
        int[] minWidths = new int[table.getColumnCount()];
        int[] maxWidths = new int[table.getColumnCount()];
 
        for(int columnIndex = 0; columnIndex < table.getColumnCount(); columnIndex++) {
            int headerWidth = headerFontMetrics.stringWidth(table.getColumnName(columnIndex));
 
            minWidths[columnIndex] = headerWidth + columnMargin;
 
            int maxWidth = getMaximalRequiredColumnWidth(table, columnIndex, headerWidth);
 
            maxWidths[columnIndex] = Math.max(maxWidth, minWidths[columnIndex]) + columnMargin;
        }
 
        adjustMaximumWidths(table, minWidths, maxWidths);
 
        for(int i = 0; i < minWidths.length; i++) {
            if(minWidths[i] > 0) {
                table.getColumnModel().getColumn(i).setMinWidth(minWidths[i]);
            }
 
            if(maxWidths[i] > 0) {
                table.getColumnModel().getColumn(i).setMaxWidth(maxWidths[i]);
 
                table.getColumnModel().getColumn(i).setWidth(maxWidths[i]);
            }
        }
    }
 
    private static void adjustMaximumWidths(JTable table, int[] minWidths, int[] maxWidths) {
        if(table.getWidth() > 0) {
            // to prevent infinite loops in exceptional situations
            int breaker = 0;
 
            // keep stealing one pixel of the maximum width of the highest column until we can fit in the width of the table
            while(sum(maxWidths) > table.getWidth() && breaker < 10000) {
                int highestWidthIndex = findLargestIndex(maxWidths);
 
                maxWidths[highestWidthIndex] -= 1;
 
                maxWidths[highestWidthIndex] = Math.max(maxWidths[highestWidthIndex], minWidths[highestWidthIndex]);
 
                breaker++;
            }
        }
    }
 
    private static int getMaximalRequiredColumnWidth(JTable table, int columnIndex, int headerWidth) {
        int maxWidth = headerWidth;
 
        TableColumn column = table.getColumnModel().getColumn(columnIndex);
 
        for(int row = 0; row < table.getModel().getRowCount() && row < MAXIMUM_ROWS; row++) {
            TableCellRenderer cellRenderer = column.getCellRenderer();
            Object value =  table.getModel().getValueAt(row, columnIndex);

            if(cellRenderer == null) {
                cellRenderer = table.getDefaultRenderer(value.getClass());
            }

            Component rendererComponent = cellRenderer.getTableCellRendererComponent(table, value,
                false,
                false,
                row,
                columnIndex);
 
            double valueWidth = rendererComponent.getPreferredSize().getWidth();

            maxWidth = (int) Math.max(maxWidth, valueWidth);
        }
 
        return maxWidth;
    }
 
    private static int findLargestIndex(int[] widths) {
        int largestIndex = 0;
        int largestValue = 0;
 
        for(int i = 0; i < widths.length; i++) {
            if(widths[i] > largestValue) {
                largestIndex = i;
                largestValue = widths[i];
            }
        }
 
        return largestIndex;
    }
 
    private static int sum(int[] widths) {
        int sum = 0;
 
        for(int width : widths) {
            sum += width;
        }
 
        return sum;
    }
 
}