package view;

import animation.canvaspanel.Graph3DPanel;
import animation.shapes.shapes3d.Area;
import controller.Controller;
import jmath.datatypes.tuples.Point3D;
import model.DataSet;
import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartPanel;
import org.jfree.chart.axis.CategoryAxis;
import org.jfree.chart.axis.NumberAxis;
import org.jfree.chart.labels.StandardPieSectionLabelGenerator;
import org.jfree.chart.plot.CategoryPlot;
import org.jfree.chart.plot.PiePlot;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.chart.renderer.category.BarRenderer;
import utils.Utils;
import utils.managers.TTManager;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.*;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.text.NumberFormat;
import java.util.Comparator;
import java.util.Date;
import java.util.concurrent.atomic.AtomicInteger;

public class WindowFrame extends MainFrame {
    private JTable packetTable;
    private JButton startButton;
    private JButton stopButton;
    private JButton changeDeviceButton;
    private JButton scrollDownButton;
    private JButton scrollUpButton;
    private JButton scrollLockButton;
    private JButton resetButton;
    private JButton saveButton;
    private JComboBox<String> filter;
    private JTabbedPane tabbedPane;
    private JTextPane packetInfo;
    private JLabel statisticLabel;
    private State currentState;

    public WindowFrame() {
        super("AUT - Packet Sniffer - 9726028", true, true);
        handlePacketTable();
        handleStartButton();
        handleStopButton();
        handleChangeDeviceButton();
        handleResetButton();
        handleTotalSizeLabel();
        handleSaveButton();
        handleFilter();
        handleNorthPanel();
        handleEastPanel();
        handleSouthPanel();
//        setState(State.CHOOSE_NI);
        setState(State.WELCOME);
    }

    private void handleEastPanel() {
        packetInfo = new JTextPane();
        packetInfo.setEditable(false);
        packetInfo.setText("Choose a Packet...");
        handleTabbedPane();
        setRightPanel(tabbedPane);
    }

    private void handleNorthPanel() {
        JPanel northPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 0, 0));

        northPanel.add(filter);
        northPanel.add(saveButton);
        northPanel.add(changeDeviceButton);
        northPanel.add(resetButton);
        northPanel.add(scrollLockButton);
        northPanel.add(scrollUpButton);
        northPanel.add(scrollDownButton);
        northPanel.add(stopButton);
        northPanel.add(startButton);
        contentPanel.add(northPanel, BorderLayout.NORTH);
    }

    private void handleSouthPanel() {
        var p = new JPanel(new BorderLayout());
        p.add(statisticLabel);
        contentPanel.add(p, BorderLayout.SOUTH);
    }

    public void setState(State state) {
        getContentPane().remove(0);
        switch (state) {
            case CHOOSE_NI -> add(new SelectNetworkInterfacePanel(e -> setState(State.MAJOR)), BorderLayout.CENTER);
            case MAJOR -> add(splitterUp, BorderLayout.CENTER);
            case WELCOME -> add(createWelcomePanel());
        }
        currentState = state;
        repaint();
        revalidate();
    }

    private JPanel createWelcomePanel() {
        var res = new JPanel(new BorderLayout());
        var cp = new Graph3DPanel();
        for (int i = 0; i < 100; i++) {
            var s = Area.cube(cp, Point3D.random().affectOnXYZ(x -> x * (Math.random() < 0.5 ? 5 : -5)), Math.random() / 5);
            cp.addRender(s);
            s.addTicks(() -> s.rotate(0.01, 0.01, 0.01));
            res.add(cp);
        }
        cp.setDynamic(true);
        cp.addTickToFirstTicksList(() -> {
            cp.zoom(1.002);
            if (TTManager.secondsAfterStart() > 4) {
                setState(State.CHOOSE_NI);
                cp.setDynamic(false);
                System.out.println("OK");
            }
        });
        return res;
    }

    private void handleTabbedPane() {
        tabbedPane = new JTabbedPane();
        tabbedPane.setOpaque(true);
        tabbedPane.setBackground(Color.DARK_GRAY.darker());

        tabbedPane.addTab("Packet Info.", new JScrollPane(packetInfo));

        var chart = ChartFactory.createPieChart("Transport Layer Protocols", DataSet.tlpStatPieDS, false, true, true);
        var plot = (PiePlot) chart.getPlot();
        plot.setCircular(true);
        plot.setLabelGenerator(new StandardPieSectionLabelGenerator("{0} = {2}", NumberFormat.getNumberInstance(), NumberFormat.getPercentInstance()));
        plot.setNoDataMessage("No data available");
        tabbedPane.addTab("TLP Stat", new ChartPanel(chart));

        chart = ChartFactory.createPieChart("Application Layer Protocols", DataSet.alpStatPieDS, false, true, true);
        plot = (PiePlot) chart.getPlot();
        plot.setCircular(true);
        plot.setLabelGenerator(new StandardPieSectionLabelGenerator("{0} = {2}", NumberFormat.getNumberInstance(), NumberFormat.getPercentInstance()));
        plot.setNoDataMessage("No data available");
        tabbedPane.addTab("ALP Stat", new ChartPanel(chart));

        var table = new JTable() {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        table.setRowHeight(30);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setModel(new DefaultTableModel(new Object[][] {}, new String[] {"No.", "IP", "Sent Packets", "Received Packets", "Size Received", "Size Sent"}));
        tabbedPane.addTab("IP Stat", new JScrollPane(table));

        chart = ChartFactory.createBarChart("IPv4 Flags Stat", "Flag",
                "Number Of Packets", DataSet.flagsDS, PlotOrientation.VERTICAL, false, true, false);
        CategoryPlot var2 = ((CategoryPlot) chart.getPlot());
        CategoryAxis var3 = var2.getDomainAxis();
        var3.setMaximumCategoryLabelWidthRatio(0.8F);
        var3.setLowerMargin(0.02D);
        var3.setUpperMargin(0.02D);
        NumberAxis var4 = (NumberAxis)var2.getRangeAxis();
        var4.setStandardTickUnits(NumberAxis.createIntegerTickUnits());
        var4.setAutoRangeIncludesZero(true);
        BarRenderer var5 = (BarRenderer)var2.getRenderer();
        var5.setDrawBarOutline(false);
        GradientPaint var6 = new GradientPaint(0.0F, 0.0F, Color.blue, 0.0F, 0.0F, new Color(0, 0, 64));
        var5.setSeriesPaint(0, var6);
        tabbedPane.addTab("Flags Stat", new ChartPanel(chart));
    }

    private void handleFilter() {
        filter = new JComboBox<>();
        filter.addItemListener(e -> {
            var item = (String) e.getItem();
            if (item == null)
                return;
            var old = DataSet.isCapturing;
            stopButton.doClick();
            startButton.setEnabled(false);
            try {
                Controller.pcapThread.asyncSetOfNIFAndFilter(DataSet.selectedNIF, item.equals("Filter") ? "" : item.toLowerCase());
            } catch (Exception ex) {
                System.err.println("Error in setting Filter.");
            } finally {
                startButton.setEnabled(true);
            }
            if (old)
                startButton.doClick();
        });
        filter.addItem("Filter");
        filter.addItem("TCP");
        filter.addItem("UDP");
        filter.addItem("ICMP");
        filter.addItem("IGMP");
        filter.addItem("GRE");
        filter.addItem("ARP");
//        filter.addActionListener(l -> {
//            var old = DataSet.isCapturing;
//            stopButton.doClick();
//            try {
//                Controller.pcapThread.asyncSetOfNIFAndFilter(DataSet.selectedNIF, Objects.requireNonNull(filter.getSelectedItem()).toString());
//            } catch (Exception e) {
//                System.err.println("Error in setting Filter.");
//            }
//            if (old)
//                Controller.pcapThread.start();
//        });
    }

    private void handleSaveButton() {
        saveButton = new JButton("Save");
        saveButton.addActionListener(e -> {
            var old = DataSet.isCapturing;
            stopButton.doClick();
            startButton.setEnabled(false);
            new Thread(() -> {
                try {
                    var fr = getFileWriter(".\\res\\data\\psniffer\\savedsessions" + System.nanoTime() + ".txt", false);
                    fr.write("$".repeat(100) + "\n");
                    var session = "#session->" + new Date() + "\n";
                    fr.write(session);
                    AtomicInteger counter = new AtomicInteger();
                    for (var p : DataSet.packetsInfo)
                        fr.write("--- Packet No:" + counter.incrementAndGet() + " --".repeat(40) + "\n" + p);
                    fr.write("#summery->" + session);
                    fr.write(DataSet.getSummery());
                    fr.close();
                } catch (IOException ioException) {
                    ioException.printStackTrace();
                } finally {
                    startButton.setEnabled(true);
                    if (old)
                        startButton.doClick();
                }
            }).start();
        });
    }

    public static FileWriter getFileWriter(String absPath, boolean append) throws IOException {
        return new FileWriter(getFile(absPath), append);
    }

    public static File getFile(String absPath) {
        var f = new File(absPath);
        if (f.exists())
            return f;
        while (absPath.lastIndexOf("\\") == absPath.length() - 1)
            absPath = absPath.substring(0, absPath.length() - 1);
        getDir(absPath.substring(0, absPath.lastIndexOf("\\")));
        try {
            f.createNewFile();
        } catch (IOException ioException) {
            ioException.printStackTrace();
        }
        return f;
    }

    public static File getDir(String absPath) {
        var f = new File(absPath);
        f.mkdirs();
        return f;
    }

    private void handleTotalSizeLabel() {
        statisticLabel = new JLabel();
    }

    private void handleResetButton() {
        resetButton = new JButton("Reset");
        resetButton.addActionListener(e -> {
            ((DefaultTableModel) packetTable.getModel()).setRowCount(0);
            DataSet.resetAll();
            packetInfo.setText("Choose a Packet...");
            ((DefaultTableModel) ((JTable) ((JViewport) ((JScrollPane)
                    tabbedPane.getComponentAt(3)).getComponent(0)).getComponent(0)).getModel()).setRowCount(0);
            System.gc();
        });
        packetTable.repaint();
    }

    private void handleScrollButtons(JScrollPane sp) {
        scrollDownButton = new JButton("Scroll Down");
        scrollDownButton.addActionListener(e -> sp.getVerticalScrollBar().setValue(sp.getVerticalScrollBar().getMaximum()));
        scrollUpButton = new JButton("Scroll Up");
        scrollUpButton.addActionListener(e -> sp.getVerticalScrollBar().setValue(sp.getVerticalScrollBar().getMinimum()));
        scrollLockButton = new JButton("Scroll Lock");
        scrollLockButton.addActionListener(
            new ActionListener() {
                private boolean isLock = false;

                @Override
                public void actionPerformed(ActionEvent e) {
                    isLock = !isLock;
                    if (isLock) {
                        sp.getVerticalScrollBar().addAdjustmentListener(l -> sp.getVerticalScrollBar().setValue(sp.getVerticalScrollBar().getMaximum()));
                        scrollLockButton.setForeground(Color.GREEN);
                    } else {
                        for (AdjustmentListener l : sp.getVerticalScrollBar().getAdjustmentListeners())
                            sp.getVerticalScrollBar().removeAdjustmentListener(l);
                        scrollLockButton.setForeground(Color.RED);
                    }
                }
           }
        );
        scrollLockButton.doClick();
    }

    private void handleChangeDeviceButton() {
        changeDeviceButton = new JButton("Change Device");
        changeDeviceButton.addActionListener(e -> {
            stopButton.doClick();
            setState(State.CHOOSE_NI);
        });
    }

    private void handleStartButton() {
        startButton = new JButton("Start");
        startButton.addActionListener(e -> {
            Controller.pcapThread.start();
            startButton.setForeground(Color.RED);
            stopButton.setForeground(Color.GREEN);
        });
    }

    private void handleStopButton() {
        stopButton = new JButton("Stop");
        stopButton.addActionListener(e -> {
            try {
                Controller.pcapThread.stop();
            } catch (Exception ignore) {}
            startButton.setForeground(Color.GREEN);
            stopButton.setForeground(Color.RED);
        });
    }

    private void handlePacketTable() {
        packetTable = new JTable() {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }

            @Override
            protected void createDefaultRenderers() {
                super.createDefaultRenderers();
            }
        };
        packetTable.setModel(new DefaultTableModel(new Object[][] {},
                new String[] {"No.", "ID", "Length", "Source IP", "Destination IP",
                        "Protocol", "Data As String", "Source MAC Address", "Destination MAC Address", "TTL", "srcPort", "dstPort"}));
        packetTable.setRowHeight(30);
        packetTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        packetTable.addKeyListener(new KeyAdapter() {
            @Override
            public void keyReleased(KeyEvent e) {
                packetInfo.setText(DataSet.packetsInfo.get(packetTable.getSelectedRow()));
            }
        });

        TableColumnModel cModel = packetTable.getColumnModel();
        cModel.setColumnSelectionAllowed(false);
//        cModel.getColumn(0).setWidth(45);
//        cModel.getColumn(1).setWidth(60);
//        cModel.getColumn(2).setWidth(70);
//        cModel.getColumn(3).setWidth(150);
//        cModel.getColumn(4).setWidth(150);
//        cModel.getColumn(5).setWidth(60);
//        cModel.getColumn(6).setWidth(100);
//        cModel.getColumn(7).setWidth(100);

//        packetTable.setAutoCreateRowSorter(true);
        TableRowSorter<TableModel> sorter = new TableRowSorter<>(packetTable.getModel());
        sorter.setComparator(0, Comparator.comparingInt(o -> Integer.parseInt(o.toString())));
        sorter.setComparator(2, Comparator.comparingInt(o -> Integer.parseInt(o.toString())));
        packetTable.setRowSorter(sorter);

        packetTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                packetInfo.setText(DataSet.packetsInfo.get(packetTable.getSelectedRow()));
            }
        });

        JScrollPane sp = new JScrollPane(packetTable);
        sp.setAutoscrolls(true);

        handleScrollButtons(sp);
        contentPanel.add(sp, BorderLayout.CENTER);
    }

    public JLabel getStatisticLabel() {
        return statisticLabel;
    }

    public void insertPacket(Object[] row) {
        DefaultTableModel model = (DefaultTableModel) packetTable.getModel();
        model.addRow(row);
        packetTable.revalidate();
        packetTable.repaint();
    }

    public JTabbedPane getTabbedPane() {
        return tabbedPane;
    }

    public State getCurrentState() {
        return currentState;
    }

    public JTextPane getPacketInfo() {
        return packetInfo;
    }

    public JButton getStartButton() {
        return startButton;
    }

    public JComboBox<String> getFilter() {
        return filter;
    }

    public JButton getStopButton() {
        return stopButton;
    }

    public enum State {
        CHOOSE_NI,
        MAJOR,
        WELCOME,
        SETTINGS
    }
}
