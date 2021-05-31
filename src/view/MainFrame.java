package view;

import javax.swing.*;
import java.awt.*;
import java.awt.event.InputEvent;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

@SuppressWarnings("unused")
public class MainFrame extends JFrame implements Runnable, Serializable {
    public static final int DEFAULT_HEIGHT = 720;
    public static final int DEFAULT_WIDTH = DEFAULT_HEIGHT * 16 / 9;

    protected boolean isFullScreen;
    protected JMenuBar menuBar;

    public final JPanel contentPanel;

    protected final JSplitPane splitterLeft;
    protected final JSplitPane splitterRight;
    protected final JSplitPane splitterUp;
    protected final JSplitPane splitterDown;

    private boolean isDarkTheme;
    private boolean isFirstCompile = true;

    protected Component leftPanel;
    protected Component rightPanel;
    protected Component southPanel;
    protected Component northPanel;

    public MainFrame(String title, boolean useSplitters, boolean isDarkTheme) {
        super(title);

        this.isDarkTheme = isDarkTheme;

        contentPanel = new JPanel(new BorderLayout());
        leftPanel = new JPanel(new BorderLayout());
        rightPanel = new JPanel(new BorderLayout());
        southPanel = new JPanel(new BorderLayout());
        northPanel = new JPanel(new BorderLayout());
        splitterLeft = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, contentPanel, null);
        splitterRight = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, null, splitterLeft);
        splitterDown = new JSplitPane(JSplitPane.VERTICAL_SPLIT, null, splitterRight);
        splitterUp = new JSplitPane(JSplitPane.VERTICAL_SPLIT, splitterDown, null);

        if (isDarkTheme)
            handleUIManager();

        init(useSplitters);
    }

    public MainFrame(String title, boolean useSplitters) {
        this(title, useSplitters, true);
    }

    public MainFrame(String title) {
        this(title, true);
    }

    public MainFrame() {
        this(null);
    }

    private void init(boolean useSplitters) {
        setLayout(new BorderLayout());
        setPreferredSize(new Dimension(DEFAULT_WIDTH, DEFAULT_HEIGHT));
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLocation(350, 200);

        isFullScreen = false;

        handleMenuBar();

        if (useSplitters) {
//            contentPanel.setMinimumSize(new Dimension(DEFAULT_WIDTH * 3 / 5, DEFAULT_HEIGHT * 3 / 5));
            handleSplitters();
        } else {
            add(contentPanel, BorderLayout.CENTER);
        }

        setJMenuBar(menuBar);
        pack();
    }

    private void handleSplitters() {
        splitterDown.setDividerSize(3);
        splitterLeft.setDividerSize(3);
        splitterRight.setDividerSize(3);
        splitterUp.setDividerSize(3);

        add(splitterUp, BorderLayout.CENTER);
    }

    private void handleMenuBar() {
        menuBar = new JMenuBar();

        JMenu helpMenu = new JMenu("Help");
        JMenu fileMenu = new JMenu("File");
        JMenu viewMenu = new JMenu("View");
        JMenu analyzeMenu = new JMenu("Analyze");

        JMenuItem hideLeftPanel = new JMenuItem("Hide Left Panel");
        hideLeftPanel.addActionListener(e -> togglePanel(1));
        hideLeftPanel.setAccelerator(KeyStroke.getKeyStroke('1', InputEvent.ALT_DOWN_MASK));
        viewMenu.add(hideLeftPanel);
        JMenuItem hideRightPanel = new JMenuItem("Hide Right Panel");
        hideRightPanel.addActionListener(e -> togglePanel(2));
        hideRightPanel.setAccelerator(KeyStroke.getKeyStroke('2', InputEvent.ALT_DOWN_MASK));
        viewMenu.add(hideRightPanel);
        JMenuItem hideNorthPanel = new JMenuItem("Hide North Panel");
        hideNorthPanel.addActionListener(e -> togglePanel(3));
        hideNorthPanel.setAccelerator(KeyStroke.getKeyStroke('3', InputEvent.ALT_DOWN_MASK));
        viewMenu.add(hideNorthPanel);
        JMenuItem hideSouthPanel = new JMenuItem("Hide South Panel");
        hideSouthPanel.addActionListener(e -> togglePanel(4));
        hideSouthPanel.setAccelerator(KeyStroke.getKeyStroke('4', InputEvent.ALT_DOWN_MASK));
        viewMenu.add(hideSouthPanel);
        JMenuItem hideAllSidePanels = new JMenuItem("Hide All Side Panels");
        hideAllSidePanels.addActionListener(e -> togglePanel(5));
        hideAllSidePanels.setAccelerator(KeyStroke.getKeyStroke('5', InputEvent.ALT_DOWN_MASK));
        viewMenu.add(hideAllSidePanels);
        JMenuItem toggleDarkTheme = new JMenuItem("Toggle Dark Theme");
        toggleDarkTheme.addActionListener(e -> toggleDarkTheme());
        toggleDarkTheme.setAccelerator(KeyStroke.getKeyStroke('t', InputEvent.ALT_DOWN_MASK));
        viewMenu.add(toggleDarkTheme);
        JMenuItem alwaysOnTop = new JMenuItem("Always On Top");
        alwaysOnTop.addActionListener(e -> setAlwaysOnTop(!isAlwaysOnTop()));
        alwaysOnTop.setAccelerator(KeyStroke.getKeyStroke('k', InputEvent.ALT_DOWN_MASK));
        viewMenu.add(alwaysOnTop);

        JMenuItem fullScreen = new JMenuItem("Full Screen");
        fullScreen.addActionListener(e -> toggleFullScreen());
        fullScreen.setAccelerator(KeyStroke.getKeyStroke("F11"));
        viewMenu.add(fullScreen);

        JMenuItem analyzeCPUByJVM = new JMenuItem("CPU Usage By JVM");
        analyzeCPUByJVM.addActionListener(e -> cpuUsageByJVMAction());
        analyzeCPUByJVM.setAccelerator(KeyStroke.getKeyStroke("F9"));
        analyzeMenu.add(analyzeCPUByJVM);

        JMenuItem quit = new JMenuItem("Quit");
        quit.addActionListener(e -> closeAction());
        quit.setAccelerator(KeyStroke.getKeyStroke('Q', InputEvent.ALT_DOWN_MASK));
        fileMenu.add(quit);

        JMenuItem tray = new JMenuItem("System Tray");
        tray.setAccelerator(KeyStroke.getKeyStroke('W', InputEvent.CTRL_DOWN_MASK));
        helpMenu.add(tray);

        menuBar.add(fileMenu);
        menuBar.add(viewMenu);
        menuBar.add(analyzeMenu);
        menuBar.add(helpMenu);

    }

    protected void closeAction() {
        System.exit(0);
    }

    private void cpuUsageByJVMAction() {
//        var dialog = new JDialog(this, "Hardware Analyzer");
//        dialog.setLocationRelativeTo(this);
//        dialog.setLayout(new BorderLayout());
//        dialog.add(new MonitoringPanel());
//        dialog.setSize(getWidth() / 2, getHeight() / 2);
//        dialog.setVisible(true);
//        splitterUp.setRightComponent(splitterUp.getRightComponent() == null ? monitoringPanel : null);
    }

    public static List<Component> getAllComponents(Container container) {
        Component[] components = container.getComponents();
        List<Component> componentList = new ArrayList<>();
        for (Component component : components) {
            componentList.add(component);
            if (component instanceof Container)
                componentList.addAll(getAllComponents((Container) component));
        }

        return componentList;
    }

    public void toggleFullScreen() {
        isFullScreen = !isFullScreen;
        setVisible(false);
        if (isFullScreen) {
            dispose();
            setUndecorated(true);
            setExtendedState(JFrame.MAXIMIZED_BOTH);
            GraphicsEnvironment.getLocalGraphicsEnvironment().getDefaultScreenDevice().setFullScreenWindow(this);
        } else {
            dispose();
            GraphicsEnvironment.getLocalGraphicsEnvironment().getDefaultScreenDevice().setFullScreenWindow(null);
            setUndecorated(false);
            setExtendedState(JFrame.NORMAL);
            setSize(1300, 720);
            setVisible(true);
        }
    }

    public void toggleDarkTheme() {
        isDarkTheme = !isDarkTheme;
        handleUIManager();
        repaint();
    }

    protected void togglePanel(int i) {
        switch (i) {
            case 1:
                splitterRight.setLeftComponent(
                        splitterRight.getLeftComponent() == null ? leftPanel : null);
                break;
            case 2:
                splitterLeft.setRightComponent(
                        splitterLeft.getRightComponent() == null ? rightPanel : null);
                break;
            case 3:
                splitterUp.setRightComponent(
                        splitterUp.getRightComponent() == null ? southPanel : null);
                break;
            case 4:
                splitterDown.setLeftComponent(
                        splitterDown.getLeftComponent() == null ? northPanel : null);
                break;
            case 5:
                for (int ii = 1; ii < 5; ii++) {
                    togglePanel(ii);
                }
                break;
        }
    }

    public void setRightPanel(Component rightPanel) {
        splitterLeft.setRightComponent(rightPanel);
        this.rightPanel = rightPanel;
    }

    public void setLeftPanel(Component leftPanel) {
        splitterRight.setLeftComponent(leftPanel);
        this.leftPanel = leftPanel;
    }

    public void setNorthPanel(Component northPanel) {
        splitterDown.setLeftComponent(northPanel);
        this.northPanel = northPanel;
    }

    public void setSouthPanel(Component southPanel) {
        splitterUp.setRightComponent(southPanel);
        this.southPanel = southPanel;
    }

    private void handleUIManager() {
        if (isFirstCompile)
            try {
                for (UIManager.LookAndFeelInfo info : UIManager.getInstalledLookAndFeels()) {
                    if ("Nimbus".equals(info.getName())) {
                        UIManager.setLookAndFeel(info.getClassName());
                        break;
                    }
                }
            } catch (Exception e) {
                System.exit(-1);
            }

        isFirstCompile = false;

        if (isDarkTheme) {
            UIManager.put("control", Color.DARK_GRAY.darker());
            UIManager.put("info", new Color(128,128,128));
            UIManager.put("nimbusBase", new Color( 18, 30, 49));
            UIManager.put("nimbusAlertYellow", new Color( 248, 187, 0));
            UIManager.put("nimbusDisabledText", new Color( 128, 128, 128));
            UIManager.put("nimbusFocus", new Color(115,164,209));
            UIManager.put("nimbusGreen", new Color(176,179,50));
            UIManager.put("nimbusInfoBlue", new Color( 66, 139, 221));
            UIManager.put("nimbusLightBackground", Color.DARK_GRAY);
            UIManager.put("nimbusOrange", new Color(191,98,4));
            UIManager.put("nimbusRed", new Color(169,46,34) );
            UIManager.put("nimbusSelectedText", new Color( 255, 255, 255));
            UIManager.put("nimbusSelectionBackground", new Color( 104, 93, 156));
            UIManager.put("text", new Color( 230, 230, 230));
        } else {
            UIManager.put("control", new Color(214,217,223));
            UIManager.put("info", new Color(242,242,189));
            UIManager.put("nimbusBase", new Color( 51,98,140));
            UIManager.put("nimbusAlertYellow", new Color( 255,220,35));
            UIManager.put("nimbusDisabledText", new Color( 142,143,145));
            UIManager.put("nimbusFocus", new Color(115,164,209));
            UIManager.put("nimbusGreen", new Color(176,179,50));
            UIManager.put("nimbusInfoBlue", new Color( 47,92,180));
            UIManager.put("nimbusLightBackground", new Color(255,255,255));
            UIManager.put("nimbusOrange", new Color(191,98,4));
            UIManager.put("nimbusRed", new Color(169,46,34) );
            UIManager.put("nimbusSelectedText", new Color( 255, 255, 255));
            UIManager.put("nimbusSelectionBackground", new Color( 57,105,138));
            UIManager.put("text", new Color( 0, 0, 0));
        }
    }

    @Override
    public void run() {
        setVisible(true);
    }
}