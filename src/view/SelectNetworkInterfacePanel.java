package view;

import insomnia.view.IconFactory;
import controller.Controller;
import model.DataSet;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.Comparator;

public class SelectNetworkInterfacePanel extends JPanel {
    private JTable table;
    private JButton selectButton;
    private JButton refreshButton;

    public SelectNetworkInterfacePanel(ActionListener... selectButtonActionListeners) {
        setLayout(new BorderLayout());
        handleTable();
        handleSouthPanel();
        for (var l : selectButtonActionListeners)
            selectButton.addActionListener(l);
        refreshButton.doClick();
    }

    private void handleSouthPanel() {
        var sp = new JPanel(new FlowLayout(FlowLayout.RIGHT, 0, 0));

        handleSelectButton();
        handleRefreshButton();

        sp.add(refreshButton);
        sp.add(selectButton);

        add(sp, BorderLayout.SOUTH);
    }

    private void handleTable() {
        table = new JTable() {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        table.setModel(new DefaultTableModel(new Object[][] {}, new String[] {"No.", "Name", "Description", "Address"}));

        var cModel = table.getColumnModel();
        cModel.getColumn(0).setMaxWidth(60);
        cModel.getColumn(0).setResizable(false);

        table.setRowHeight(35);
        table.getSelectionModel().setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        var sorter = new TableRowSorter<>(table.getModel());
        sorter.setComparator(0, Comparator.comparingInt(o -> Integer.parseInt(o.toString())));
        sorter.setComparator(2, (Comparator<String>) CharSequence::compare);
        table.setRowSorter(sorter);

        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2)
                    selectButton.doClick();
            }
        });

        table.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                var c = (JComponent) super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                c.setForeground(IconFactory.randomColor());
                return c;
            }
        });

        add(new JScrollPane(table), BorderLayout.CENTER);
    }

    private void handleSelectButton() {
        selectButton = new JButton("Select");

        selectButton.addActionListener(e -> System.out.println(table.getValueAt(table.getSelectedRow(), 1)));
        selectButton.addActionListener(e -> DataSet.selectedNIF = (String) table.getValueAt(table.getSelectedRow(), 1));
        selectButton.addActionListener(e -> Controller.pcapThread.asyncSetOfNIFAndFilter(table.getValueAt(table.getSelectedRow(), 1).toString(), ""));
        selectButton.addActionListener(e -> Controller.window.getStopButton().doClick());
        selectButton.addActionListener(e -> Controller.window.getFilter().setSelectedIndex(0));
    }

    private void handleRefreshButton() {
        refreshButton = new JButton("Refresh");
        refreshButton.addActionListener(e -> {
            var m = (DefaultTableModel) table.getModel();
            m.setRowCount(0);
            try {
                var nifList = Pcaps.findAllDevs();
                int counter = 0;
                for (var nif : nifList)
                    m.addRow(new Object[] {
                            ++counter, nif.getName(), nif.getDescription(), nif.getAddresses().get(0).getAddress()
                    });
            } catch (PcapNativeException pcapNativeException) {
                pcapNativeException.printStackTrace();
            }
        });
    }
}
