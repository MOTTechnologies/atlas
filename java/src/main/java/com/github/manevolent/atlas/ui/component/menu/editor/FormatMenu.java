package com.github.manevolent.atlas.ui.component.menu.editor;

import com.github.manevolent.atlas.model.ArithmeticOperation;
import com.github.manevolent.atlas.model.DataFormat;
import com.github.manevolent.atlas.model.Scale;
import com.github.manevolent.atlas.model.Unit;
import com.github.manevolent.atlas.ui.Editor;
import com.github.manevolent.atlas.ui.util.Errors;
import com.github.manevolent.atlas.ui.util.Layout;
import com.github.manevolent.atlas.ui.util.Menus;
import org.kordamp.ikonli.carbonicons.CarbonIcons;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.swing.*;
import javax.swing.event.AncestorEvent;
import javax.swing.event.AncestorListener;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.IOException;
import java.io.StringReader;
import java.util.LinkedHashMap;
import java.util.Map;

public class FormatMenu extends EditorMenu {
    private static final Map<String, Unit> ssm4UnitMap = new LinkedHashMap<>();
    static {
        ssm4UnitMap.put("IDS_UNIT_A", Unit.AMPERE);
        ssm4UnitMap.put("IDS_UNIT_MA", Unit.MILLIAMPERE);

        ssm4UnitMap.put("IDS_UNIT_RPM", Unit.RPM);

        ssm4UnitMap.put("IDS_UNIT_PERCENT", Unit.PERCENT);
        ssm4UnitMap.put("IDS_UNIT_GS", Unit.G_PER_SEC);
        ssm4UnitMap.put("IDS_UNIT_KPA", Unit.KPA);
        ssm4UnitMap.put("IDS_UNIT_MPA", Unit.MPA);
        ssm4UnitMap.put("IDS_UNIT_DEG", Unit.DEGREES);
        ssm4UnitMap.put("IDS_UNIT_RESI", Unit.OHM);
        ssm4UnitMap.put("IDS_UNIT_DEG_C", Unit.CELSIUS);
        ssm4UnitMap.put("IDS_UNIT_MS", Unit.MILLISECOND);
        ssm4UnitMap.put("IDS_UNIT_SDIC1200", Unit.MICROSECOND);
        ssm4UnitMap.put("IDS_UNIT_KM", Unit.KILOMETER);
        ssm4UnitMap.put("IDS_UNIT_KMH", Unit.KMH);

        ssm4UnitMap.put("IDS_UNIT_V", Unit.VOLTS);
        ssm4UnitMap.put("IDS_UNIT_SEC", Unit.SECOND);

        ssm4UnitMap.put("IDS_UNIT_DO", Unit.DEGREES);
    }

    public FormatMenu(Editor editor) {
        super(editor);
    }

    @Override
    protected void initComponent(JMenu menu) {
        menu.setText("Format");

        menu.add(Menus.item(CarbonIcons.DATA_SET, "New Format...", (e) -> getEditor().newFormat()));
        menu.addSeparator();
        menu.add(Menus.item(CarbonIcons.CODE, "Import SSM4 Scale...", this::importSSM4Scale));
    }

    private void importSSM4Pids(ActionEvent event) {

    }

    public static Object showXmlDialog(Frame parent, String message, String title, String initial) {
        JTextField renameField = new JTextField(initial);
        Layout.preferWidth(renameField, 400);

        BorderLayout layout = new BorderLayout();
        JPanel topPanel = new JPanel(layout);

        topPanel.addAncestorListener(new AncestorListener() {
            @Override
            public void ancestorAdded(AncestorEvent event) {
                renameField.grabFocus();
            }

            @Override
            public void ancestorRemoved(AncestorEvent event) {

            }

            @Override
            public void ancestorMoved(AncestorEvent event) {

            }
        });

        JLabel label = new JLabel(message);
        label.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 0));
        topPanel.add(label, BorderLayout.NORTH);
        JPanel centerPanel = new JPanel(new BorderLayout(5, 5));
        centerPanel.add(renameField, BorderLayout.CENTER);
        topPanel.add(centerPanel);

        int res = JOptionPane.showConfirmDialog(parent, topPanel, title, JOptionPane.OK_CANCEL_OPTION);
        if (res == JOptionPane.OK_OPTION) {
            return renameField.getText();
        } else {
            return null;
        }
    }

    private void importSSM4Scale(ActionEvent actionEvent) {
        try {
            importSSM4Scale();
        } catch (Exception e) {
            Errors.show(getEditor(), "Import Failed", "Failed to import SSM4 Scale!", e);
        }
    }

    private void importSSM4Scale() throws ParserConfigurationException, IOException, SAXException {
        String xml = (String) showXmlDialog(getEditor(), "Enter PID XML:", "Import SSM4 Scale", "");

        if (xml == null) {
            return;
        }

        Scale scale = importSSM4Scale(xml);
        getEditor().openScale(scale);
    }

    public static Scale importSSM4Scale(String xml) throws ParserConfigurationException, IOException, SAXException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.parse(new InputSource(new StringReader(xml)));
        Element rootElement = document.getDocumentElement();

        if (!rootElement.getNodeName().equalsIgnoreCase("pid")) {
            throw new UnsupportedOperationException("Unexpected node name: " + rootElement.getNodeName());
        }

        Scale.Builder scaleBuilder = Scale.builder();
        scaleBuilder.withName("PIDs - " + rootElement.getAttribute("PidNo").substring(1)
                + " (" + rootElement.getAttribute("SignalName") + ")");

        int bitSize = Integer.parseInt(rootElement.getAttribute("BitSize"));
        boolean signed = Integer.parseInt(rootElement.getAttribute("Sign")) == 1;
        boolean endian = Integer.parseInt(rootElement.getAttribute("Endian")) == 1;
        boolean littleEndian = !endian;
        boolean bigEndian = endian;
        switch (bitSize) {
            case 8:
                scaleBuilder.withFormat(signed ? DataFormat.SBYTE : DataFormat.UBYTE);
                break;
            case 16:
                scaleBuilder.withFormat(signed ? DataFormat.SSHORT : DataFormat.USHORT);
                break;
            default:
                throw new UnsupportedOperationException("Unsupported BitSize: " + bitSize);
        }

        if (rootElement.hasAttribute("Unit")) {
            String unitName = rootElement.getAttribute("Unit");
            scaleBuilder.withUnit(ssm4UnitMap.getOrDefault(unitName, Unit.NONE));
        } else {
            scaleBuilder.withUnit(Unit.NONE);
        }

        int convMethod = Integer.parseInt(rootElement.getAttribute("ConvMethod"));
        switch (convMethod) {
            case 1:
                // Flag
                throw new UnsupportedOperationException();
            case 2:
                if (rootElement.hasAttribute("LsbDiv")) {
                    int lsbDiv = Integer.parseInt(rootElement.getAttribute("LsbDiv"));
                    if (lsbDiv != 1) {
                        scaleBuilder.withOperation(ArithmeticOperation.DIVIDE, lsbDiv);
                    }
                }

                if (rootElement.hasAttribute("LsbMul") &&
                        rootElement.hasAttribute("Significant") &&
                        rootElement.hasAttribute("Offset") &&

                        Integer.parseInt(rootElement.getAttribute("LsbMul"))
                                == Math.pow(10, Integer.parseInt(rootElement.getAttribute("Significant")))
                        && Integer.parseInt(rootElement.getAttribute("Offset")) == 0) {
                    break;
                }

                if (rootElement.hasAttribute("LsbMul")) {
                    int lsbMul = Integer.parseInt(rootElement.getAttribute("LsbMul"));
                    if (lsbMul != 1) {
                        scaleBuilder.withOperation(ArithmeticOperation.MULTIPLY, lsbMul);
                    }
                }

                if (rootElement.hasAttribute("Offset")) {
                    int offset = Integer.parseInt(rootElement.getAttribute("Offset"));
                    if (offset > 0) {
                        scaleBuilder.withOperation(ArithmeticOperation.ADD, offset);
                    } else if (offset < 0) {
                        scaleBuilder.withOperation(ArithmeticOperation.SUBTRACT, Math.abs(offset));
                    }
                }

                if (rootElement.hasAttribute("Significant")) {
                    int significant = Integer.parseInt(rootElement.getAttribute("Significant"));
                    scaleBuilder.withOperation(ArithmeticOperation.DIVIDE, (float) Math.pow(10, significant));
                }

                break;
            default:
                throw new UnsupportedOperationException("Unsupported ConvMethod: " + convMethod);
        }

        return scaleBuilder.build();
    }
}
