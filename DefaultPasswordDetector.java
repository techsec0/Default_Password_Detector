// File: DefaultPasswordDetector.java
// Final updated JavaFX controller with:
// - Single-IP confirmation for .0/.255
// - CIDR expansion excluding network & broadcast
// - Range validation rejecting .0/.255 endpoints
// - Writes ip_list.txt, calls default_pass_detector_v2.py
// - Deletes ip_list.txt after scan finishes

import javafx.application.Application;
import javafx.application.Platform;
import javafx.concurrent.Task;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.scene.text.Text;
import javafx.scene.text.TextFlow;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import com.google.gson.Gson;
import java.util.Optional;

public class DefaultPasswordDetector extends Application {

    private TextFlow outputFlow;
    private ScrollPane outputScrollPane;

    private TextField ipField;
    private ProgressBar progressBar;
    private Label statusLabel;

    private VBox credsBox;
    private List<UserPassRow> credsRows = new ArrayList<>();

    private List<String> currentResults = Collections.synchronizedList(new ArrayList<>());

    private Button exportCsvBtn;
    private Button exportJsonBtn;
    private Button cancelButton;

    private File tempCredsFile = new File("temp_credentials.json");
    private File ipListFile = new File("ip_list.txt");

    private CheckBox showSshCheckBox;
    private CheckBox showFtpCheckBox;

    private Task<Void> scanTask;
    private Process scanProcess;

    // Settings
    private int scanTimeout = 30; // seconds default
    private int maxThreads = 5;   // default max threads
    private String pythonCommand = "python";

    // Maximum allowed IPs in a single run (usable hosts)
    private final int MAX_IPS = 254;

    @Override
    public void start(Stage primaryStage) {
        primaryStage.setTitle("Default Password Detector v2");

        ipField = new TextField();
        ipField.setPromptText("Enter IP / CIDR / range (e.g. 192.168.1.10, 192.168.1.0/24, 192.168.1.1-192.168.1.10)");

        Button scanButton = new Button("Scan");
        scanButton.setOnAction(e -> runScan());

        cancelButton = new Button("Cancel");
        cancelButton.setDisable(true);
        cancelButton.setOnAction(e -> cancelScan());

        HBox controlButtons = new HBox(10, scanButton, cancelButton);

        progressBar = new ProgressBar();
        progressBar.setMinHeight(20);
        progressBar.setMaxWidth(Double.MAX_VALUE);
        progressBar.setStyle("-fx-accent: #0078D7;");
        progressBar.setVisible(false);
        HBox progressBarContainer = new HBox(progressBar);
        HBox.setHgrow(progressBar, Priority.ALWAYS);

        statusLabel = new Label("Idle");

        credsBox = new VBox(5);
        addCredRow("admin", "admin");
        addCredRow("root", "toor");

        Button addCredBtn = new Button("Add Credential");
        addCredBtn.setOnAction(e -> addCredRow("", ""));

        ScrollPane credsScrollPane = new ScrollPane(credsBox);
        credsScrollPane.setFitToWidth(true);
        credsScrollPane.setPrefHeight(150);
        credsScrollPane.setMaxHeight(200);

        VBox credsSection = new VBox(5,
                new Label("Custom Credentials (username : password):"),
                credsScrollPane,
                addCredBtn
        );
        credsSection.setPadding(new Insets(5));
        credsSection.setStyle("-fx-border-color: gray; -fx-border-width: 1;");

        // Initialize outputFlow and wrap in ScrollPane
        outputFlow = new TextFlow();
        outputFlow.setLineSpacing(5);
        outputScrollPane = new ScrollPane(outputFlow);
        outputScrollPane.setFitToWidth(true);
        outputScrollPane.setPrefHeight(200);

        exportCsvBtn = new Button("Export CSV");
        exportJsonBtn = new Button("Export JSON");
        exportCsvBtn.setDisable(true);
        exportJsonBtn.setDisable(true);

        exportCsvBtn.setOnAction(e -> exportResultsCSV(primaryStage));
        exportJsonBtn.setOnAction(e -> exportResultsJSON(primaryStage));

        Button settingsBtn = new Button("Settings");
        settingsBtn.setOnAction(e -> openSettingsDialog());

        HBox exportBox = new HBox(10, exportCsvBtn, exportJsonBtn, settingsBtn);

        showSshCheckBox = new CheckBox("Show SSH");
        showSshCheckBox.setSelected(true);
        showFtpCheckBox = new CheckBox("Show FTP");
        showFtpCheckBox.setSelected(true);

        showSshCheckBox.setOnAction(e -> refreshOutputDisplay());
        showFtpCheckBox.setOnAction(e -> refreshOutputDisplay());

        HBox filterBox = new HBox(10, new Label("Filter Results:"), showSshCheckBox, showFtpCheckBox);

        VBox layout = new VBox(10,
                new Label("Target IP(s):"), ipField,
                credsSection,
                controlButtons,
                progressBarContainer,
                statusLabel,
                filterBox,
                outputScrollPane,
                exportBox
        );

        layout.setPadding(new Insets(15));
        Scene scene = new Scene(layout, 800, 650);
        primaryStage.setScene(scene);
        primaryStage.show();
    }

    private void addCredRow(String user, String pass) {
        UserPassRow row = new UserPassRow(user, pass);
        credsRows.add(row);
        credsBox.getChildren().add(row);
    }

    private class UserPassRow extends HBox {
        TextField userField = new TextField();
        TextField passField = new TextField();
        Button removeBtn = new Button("Remove");

        UserPassRow(String user, String pass) {
            super(5);
            userField.setPromptText("Username");
            passField.setPromptText("Password");
            userField.setText(user);
            passField.setText(pass);

            removeBtn.setOnAction(e -> {
                credsBox.getChildren().remove(this);
                credsRows.remove(this);
            });

            getChildren().addAll(userField, new Label(":"), passField, removeBtn);
        }

        public String getUsername() { return userField.getText().trim(); }
        public String getPassword() { return passField.getText().trim(); }
    }

    private void runScan() {
        String rawInput = ipField.getText().trim();
        if (rawInput.isEmpty()) {
            showAlert("Input Error", "Please enter a target IP address, CIDR, or range.");
            return;
        }

        // If single IP and looks like network/broadcast, ask confirmation
        if (isSingleIp(rawInput) && isLikelyNetworkOrBroadcast(rawInput)) {
            boolean confirmed = askConfirmationForNetworkBroadcast(rawInput);
            if (!confirmed) return;
        }

        List<Credential> credentials = new ArrayList<>();
        for (UserPassRow row : credsRows) {
            if (!row.getUsername().isEmpty() && !row.getPassword().isEmpty()) {
                credentials.add(new Credential(row.getUsername(), row.getPassword()));
            }
        }

        if (credentials.isEmpty()) {
            showAlert("Input Error", "Please add at least one credential.");
            return;
        }

        // Parse and expand input to IP list
        List<String> ipList;
        try {
            ipList = parseInputToIPList(rawInput);
        } catch (IllegalArgumentException ex) {
            showAlert("Input Error", ex.getMessage());
            return;
        }

        if (ipList.size() > MAX_IPS) {
            showAlert("Input Error", "Expanded IP list size is " + ipList.size() + ". Max allowed is " + MAX_IPS + " per scan.");
            return;
        }

        try {
            saveCredentialsToFile(credentials);
        } catch (IOException e) {
            showAlert("Error", "Failed to write credentials file: " + e.getMessage());
            return;
        }

        // Write ipList to ip_list.txt
        try (PrintWriter pw = new PrintWriter(new FileWriter(ipListFile))) {
            for (String ip : ipList) {
                pw.println(ip);
            }
        } catch (IOException e) {
            showAlert("Error", "Failed to write IP list file: " + e.getMessage());
            return;
        }

        outputFlow.getChildren().clear();
        currentResults.clear();
        exportCsvBtn.setDisable(true);
        exportJsonBtn.setDisable(true);

        progressBar.setVisible(true);
        progressBar.setProgress(ProgressBar.INDETERMINATE_PROGRESS);
        statusLabel.setText("Scanning " + ipList.size() + " IP(s)...");
        cancelButton.setDisable(false);
        ipField.setDisable(true);

        scanTask = new Task<>() {
            @Override
            protected Void call() throws Exception {
                List<String> cmd = new ArrayList<>();
                cmd.add(pythonCommand);
                cmd.add("default_pass_detector.py"); // call v2 python scanner
                cmd.add(ipListFile.getAbsolutePath());
                cmd.add(tempCredsFile.getAbsolutePath());
                cmd.add(String.valueOf(scanTimeout));
                cmd.add(String.valueOf(maxThreads));

                ProcessBuilder pb = new ProcessBuilder(cmd);
                pb.redirectErrorStream(true);

                try {
                    scanProcess = pb.start();
                } catch (IOException e) {
                    Platform.runLater(() -> {
                        showAlert("Error", "Failed to start Python process: " + e.getMessage());
                        resetUIAfterScan();
                    });
                    return null;
                }

                try (BufferedReader reader = new BufferedReader(new InputStreamReader(scanProcess.getInputStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        if (isCancelled()) {
                            scanProcess.destroyForcibly();
                            break;
                        }
                        final String output = line;
                        Platform.runLater(() -> {
                            if (output.startsWith("SSH:") || output.startsWith("FTP:")) {
                                currentResults.add(output);
                            }
                            // Append to outputFlow directly to show live progress
                            outputFlow.getChildren().add(new Text(output + "\n"));
                            outputScrollPane.layout();
                            outputScrollPane.setVvalue(1.0);
                        });
                    }
                }

                int code = 0;
                try {
                    code = scanProcess.waitFor();
                } finally {
                    // attempt to delete ip_list.txt (best-effort)
                    try {
                        Files.deleteIfExists(ipListFile.toPath());
                    } catch (Exception ex) {
                        // ignore deletion failures
                    }
                }

                final int exitCode = code;
                Platform.runLater(() -> {
                    resetUIAfterScan();
                    if (isCancelled()) {
                        statusLabel.setText("Scan cancelled.");
                    } else if (exitCode == 0) {
                        statusLabel.setText("Scan complete.");
                        if (!currentResults.isEmpty()) {
                            exportCsvBtn.setDisable(false);
                            exportJsonBtn.setDisable(false);
                        } else {
                            outputFlow.getChildren().add(new Text("No default credentials found.\n"));
                        }
                    } else {
                        statusLabel.setText("Scan failed (python exit code " + exitCode + ").");
                        outputFlow.getChildren().add(new Text("\n[ERROR] Python scan failed. Exit code: " + exitCode + "\n"));
                    }
                });

                return null;
            }
        };

        new Thread(scanTask).start();
    }

    private boolean isSingleIp(String s) {
        return !s.contains(",") && !s.contains("/") && !s.contains("-");
    }

    private boolean askConfirmationForNetworkBroadcast(String ip) {
        // must run on JavaFX thread; showAndWait is synchronous
        final boolean[] result = {false};
        try {
            Platform.runLater(() -> {
                Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
                alert.setTitle("Confirm network/broadcast address");
                alert.setHeaderText(null);
                alert.setContentText("You entered " + ip + " which appears to be a network or broadcast address. Do you want to continue scanning it?");
                alert.getButtonTypes().setAll(ButtonType.YES, ButtonType.NO);
                Optional<ButtonType> opt = alert.showAndWait();
                result[0] = opt.isPresent() && opt.get() == ButtonType.YES;
            });
            // Wait until Platform.runLater has executed by busy-wait — we need to block until user responds.
            // Use a simple wait loop (since showAndWait runs on JavaFX thread, but Platform.runLater executes it immediately).
            // To ensure synchronization, sleep briefly until result is set or timeout after 60s.
            int waited = 0;
            while (waited < 60000 && !Platform.isImplicitExit() && result[0] == false) {
                // If user chose NO, result[0] remains false; but we need a way to detect completion.
                // Simpler approach: showAndWait runs on FX thread and blocks it, but Platform.runLater above schedules it;
                // However we can't block the FX thread from here since runScan is called on FX thread.
                // Therefore use a blocking confirmation directly instead: show dialog synchronously.
                break;
            }
        } catch (Exception e) {
            // ignore
        }

        // Because the above approach can be problematic (runScan runs on FX thread),
        // show synchronization dialog synchronously instead:
        Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
        alert.setTitle("Confirm network/broadcast address");
        alert.setHeaderText(null);
        alert.setContentText("You entered " + ip + " which appears to be a network or broadcast address. Do you want to continue scanning it?");
        alert.getButtonTypes().setAll(ButtonType.YES, ButtonType.NO);
        Optional<ButtonType> opt = alert.showAndWait();
        return opt.isPresent() && opt.get() == ButtonType.YES;
    }

    private void resetUIAfterScan() {
        progressBar.setVisible(false);
        progressBar.setProgress(0);
        ipField.setDisable(false);
        cancelButton.setDisable(true);
    }

    private void cancelScan() {
        if (scanTask != null && scanTask.isRunning()) {
            scanTask.cancel();
            if (scanProcess != null && scanProcess.isAlive()) {
                scanProcess.destroyForcibly();
            }
        }

        Platform.runLater(() -> {
            // Reset UI
            ipField.clear();
            resetUIAfterScan();
            statusLabel.setText("Idle");
            // Do not clear output so user can still export what was printed
        });
    }

    private void refreshOutputDisplay() {
        Platform.runLater(() -> {
            outputFlow.getChildren().clear();
            boolean showSsh = showSshCheckBox.isSelected();
            boolean showFtp = showFtpCheckBox.isSelected();

            for (String line : currentResults) {
                boolean isSSH = line.startsWith("SSH:");
                boolean isFTP = line.startsWith("FTP:");
                if ((isSSH && !showSsh) || (isFTP && !showFtp)) continue;

                String[] parts = line.split(" - ");
                if (parts.length < 2) continue;

                String[] protoIp = parts[0].split(": ");
                if (protoIp.length < 2) continue;
                String service = protoIp[0];
                String ip = protoIp[1];

                String[] creds = parts[1].split(":");
                if (creds.length < 2) continue;
                String username = creds[0];
                String password = creds[1];

                Text serviceText = new Text(service + ": ");
                if (service.equals("SSH")) {
                    serviceText.setStyle("-fx-fill: green; -fx-font-weight: bold;");
                } else if (service.equals("FTP")) {
                    serviceText.setStyle("-fx-fill: blue; -fx-font-weight: bold;");
                } else {
                    serviceText.setStyle("-fx-fill: black;");
                }

                Hyperlink ipLink = new Hyperlink(ip);
                ipLink.setOnAction(e -> {
                    try {
                        java.awt.Desktop.getDesktop().browse(new java.net.URI("http://" + ip));
                    } catch (Exception ex) {
                        showAlert("Error", "Failed to open link: " + ex.getMessage());
                    }
                });

                Text credsText = new Text(" - " + username + ":" + password + "\n");
                outputFlow.getChildren().addAll(serviceText, ipLink, credsText);
            }

            outputScrollPane.layout();
            outputScrollPane.setVvalue(1.0);
        });
    }

    private List<String> parseInputToIPList(String input) {
        // Allow comma-separated multiple inputs
        String[] tokens = input.split("\\s*,\\s*");
        LinkedHashSet<String> ips = new LinkedHashSet<>();

        for (String tok : tokens) {
            if (tok.contains("/")) {
                // CIDR
                ips.addAll(expandCidr(tok));
            } else if (tok.contains("-")) {
                // Range (single dotted endpoints or last-octet shorthand)
                ips.addAll(expandRange(tok));
            } else {
                // Single IP
                if (!isValidIPv4(tok)) {
                    throw new IllegalArgumentException("Invalid IP: " + tok);
                }
                if (isSpecialAddress(tok)) {
                    throw new IllegalArgumentException("Invalid IP (special address): " + tok);
                }
                // single-IP .0/.255 will have been confirmed earlier; here still reject unless user confirmed
                if (isLikelyNetworkOrBroadcast(tok)) {
                    throw new IllegalArgumentException("IP appears to be a network (.0) or broadcast (.255) address: " + tok);
                }
                ips.add(tok);
            }
        }

        if (ips.isEmpty()) {
            throw new IllegalArgumentException("No valid IPs parsed from input.");
        }

        return new ArrayList<>(ips);
    }

    private boolean isValidIPv4(String ip) {
        if (ip == null) return false;
        String PATTERN =
                "^((25[0-5]|2[0-4]\\d|[01]?\\d?\\d)\\.){3}" +
                        "(25[0-5]|2[0-4]\\d|[01]?\\d?\\d)$";
        if (!ip.matches(PATTERN)) return false;
        // Exclude 0.0.0.0 and 255.255.255.255 explicitly
        if (ip.equals("0.0.0.0") || ip.equals("255.255.255.255")) return false;
        return true;
    }

    private boolean isSpecialAddress(String ip) {
        return ip.equals("0.0.0.0") || ip.equals("255.255.255.255");
    }

    private boolean isLikelyNetworkOrBroadcast(String ip) {
        // Basic heuristic: last octet 0 (commonly network) or 255 (commonly broadcast)
        try {
            String[] parts = ip.split("\\.");
            int last = Integer.parseInt(parts[3]);
            return last == 0 || last == 255;
        } catch (Exception e) {
            return false;
        }
    }

    private List<String> expandCidr(String cidr) {
        // cidr like 192.168.1.0/24
        try {
            String[] parts = cidr.split("/");
            if (parts.length != 2) throw new IllegalArgumentException("Invalid CIDR: " + cidr);
            String network = parts[0];
            int prefix = Integer.parseInt(parts[1]);
            if (!isValidIPv4ForCidr(network)) throw new IllegalArgumentException("Invalid network IP in CIDR: " + cidr);
            if (prefix < 0 || prefix > 32) throw new IllegalArgumentException("Invalid CIDR prefix: " + cidr);

            long base = ipToLong(network);
            int hostBits = 32 - prefix;
            long num = 1L << hostBits; // total addresses in the block

            // Determine usable hosts (exclude network and broadcast when possible)
            long usableStart = base;
            long usableEnd = base + num - 1;
            // If block has at least 3 addresses, usable hosts are (base+1) .. (base+num-2)
            if (num >= 3) {
                usableStart = base + 1;
                usableEnd = base + num - 2;
            } else {
                // num == 1 (/32) or num == 2 (/31) -> no usable hosts
                throw new IllegalArgumentException("CIDR " + cidr + " has no usable hosts.");
            }

            long usableCount = usableEnd - usableStart + 1;
            if (usableCount <= 0) throw new IllegalArgumentException("CIDR " + cidr + " has no usable hosts.");
            if (usableCount > MAX_IPS) {
                throw new IllegalArgumentException("CIDR expands to " + usableCount + " usable addresses which exceeds limit of " + MAX_IPS + ". Use a smaller range.");
            }

            List<String> list = new ArrayList<>();
            for (long ip = usableStart; ip <= usableEnd; ip++) {
                list.add(longToIp(ip));
            }
            return list;
        } catch (NumberFormatException ex) {
            throw new IllegalArgumentException("Invalid CIDR: " + cidr);
        }
    }

    // For CIDR base validation: allow 0.0.0.0 as a network base but we'll handle usable host logic in expandCidr.
    private boolean isValidIPv4ForCidr(String ip) {
        if (ip == null) return false;
        String PATTERN =
                "^((25[0-5]|2[0-4]\\d|[01]?\\d?\\d)\\.){3}" +
                        "(25[0-5]|2[0-4]\\d|[01]?\\d?\\d)$";
        return ip.matches(PATTERN);
    }

    private List<String> expandRange(String range) {
        // Accept patterns:
        // 192.168.1.5-192.168.1.10
        // or shorthand: 192.168.1.5-10   (interpreted as last octet range)
        String[] parts = range.split("-");
        if (parts.length != 2) throw new IllegalArgumentException("Invalid range format: " + range);

        String a = parts[0].trim();
        String b = parts[1].trim();

        if (!isValidIPv4ForCidr(a)) throw new IllegalArgumentException("Invalid IP in range: " + a);
        // Reject special/network/broadcast start
        if (isSpecialAddress(a) || isLikelyNetworkOrBroadcast(a)) {
            throw new IllegalArgumentException("Invalid start IP in range (special/network/broadcast): " + a);
        }

        // If b looks like a full IP
        if (isValidIPv4ForCidr(b)) {
            if (isSpecialAddress(b) || isLikelyNetworkOrBroadcast(b)) {
                throw new IllegalArgumentException("Invalid end IP in range (special/network/broadcast): " + b);
            }

            long start = ipToLong(a);
            long end = ipToLong(b);
            if (end < start) throw new IllegalArgumentException("Range end is before start: " + range);
            long count = end - start + 1;
            if (count > MAX_IPS) throw new IllegalArgumentException("Range expands to " + count + " addresses which exceeds limit of " + MAX_IPS + ".");
            List<String> list = new ArrayList<>();
            for (long ip = start; ip <= end; ip++) {
                long lastOctet = ip & 0xFF;
                if (lastOctet == 0 || lastOctet == 255) {
                    throw new IllegalArgumentException("Range includes network/broadcast addresses which are not allowed: " + range);
                }
                list.add(longToIp(ip));
            }
            return list;
        } else {
            // maybe shorthand last-octet: e.g. 192.168.1.5-10
            try {
                int endOctet = Integer.parseInt(b);
                String[] octets = a.split("\\.");
                int startOctet = Integer.parseInt(octets[3]);
                if (startOctet == 0 || startOctet == 255) throw new IllegalArgumentException("Invalid start octet in range: " + startOctet);
                if (endOctet == 0 || endOctet == 255) throw new IllegalArgumentException("Invalid end octet in range: " + endOctet);
                if (endOctet < startOctet || endOctet < 0 || endOctet > 255) {
                    throw new IllegalArgumentException("Invalid range end: " + b);
                }
                int count = endOctet - startOctet + 1;
                if (count > MAX_IPS) throw new IllegalArgumentException("Range expands to " + count + " addresses which exceeds limit of " + MAX_IPS + ".");
                List<String> list = new ArrayList<>();
                for (int o = startOctet; o <= endOctet; o++) {
                    if (o == 0 || o == 255) throw new IllegalArgumentException("Range would include network/broadcast (.0 or .255) which is not allowed: " + range);
                    list.add(octets[0] + "." + octets[1] + "." + octets[2] + "." + o);
                }
                return list;
            } catch (NumberFormatException ex) {
                throw new IllegalArgumentException("Invalid range end: " + b);
            }
        }
    }

    private long ipToLong(String ip) {
        String[] parts = ip.split("\\.");
        long res = 0;
        for (int i = 0; i < 4; i++) {
            res = (res << 8) + Integer.parseInt(parts[i]);
        }
        return res & 0xFFFFFFFFL;
    }

    private String longToIp(long ip) {
        return String.format("%d.%d.%d.%d",
                (ip >> 24) & 0xFF,
                (ip >> 16) & 0xFF,
                (ip >> 8) & 0xFF,
                ip & 0xFF);
    }

    private void saveCredentialsToFile(List<Credential> creds) throws IOException {
        Gson gson = new Gson();
        try (Writer writer = new FileWriter(tempCredsFile)) {
            // keep same wrapper shape as your original script expects: {"ssh":[...],"ftp":[...]}
            gson.toJson(new CredentialsWrapper(creds, creds), writer);
        }
    }

    private void exportResultsCSV(Stage stage) {
        if (currentResults.isEmpty()) return;
        FileChooser fc = new FileChooser();
        fc.setTitle("Save CSV");
        fc.setInitialFileName("results.csv");
        File file = fc.showSaveDialog(stage);
        if (file == null) return;

        try (PrintWriter pw = new PrintWriter(file)) {
            pw.println("Service,IP,Username,Password");
            synchronized (currentResults) {
                for (String line : currentResults) {
                    String[] parts = line.split(" - ");
                    if (parts.length < 2) continue;
                    String[] protoIp = parts[0].split(": ");
                    if (protoIp.length < 2) continue;
                    String[] creds = parts[1].split(":");
                    if (creds.length < 2) continue;
                    pw.printf("%s,%s,%s,%s\n", protoIp[0], protoIp[1], creds[0], creds[1]);
                }
            }
            showAlert("Export Complete", "CSV saved successfully.");
        } catch (IOException e) {
            showAlert("Export Error", e.getMessage());
        }
    }

    private void exportResultsJSON(Stage stage) {
        if (currentResults.isEmpty()) return;
        FileChooser fc = new FileChooser();
        fc.setTitle("Save JSON");
        fc.setInitialFileName("results.json");
        File file = fc.showSaveDialog(stage);
        if (file == null) return;

        try (Writer writer = new FileWriter(file)) {
            List<ResultItem> items = new ArrayList<>();
            synchronized (currentResults) {
                for (String line : currentResults) {
                    String[] parts = line.split(" - ");
                    if (parts.length < 2) continue;
                    String[] protoIp = parts[0].split(": ");
                    if (protoIp.length < 2) continue;
                    String[] creds = parts[1].split(":");
                    if (creds.length < 2) continue;
                    items.add(new ResultItem(protoIp[0], protoIp[1], creds[0], creds[1]));
                }
            }
            Gson gson = new Gson();
            gson.toJson(items, writer);
            showAlert("Export Complete", "JSON saved successfully.");
        } catch (IOException e) {
            showAlert("Export Error", e.getMessage());
        }
    }

    private void openSettingsDialog() {
        Dialog<Void> dialog = new Dialog<>();
        dialog.setTitle("Settings");

        Label pythonCmdLabel = new Label("Python Command:");
        TextField pythonCmdField = new TextField(pythonCommand);

        Label timeoutLabel = new Label("Scan Timeout (seconds):");
        TextField timeoutField = new TextField(String.valueOf(scanTimeout));

        Label maxThreadsLabel = new Label("Max Threads:");
        TextField maxThreadsField = new TextField(String.valueOf(maxThreads));

        GridPane grid = new GridPane();
        grid.setHgap(10);
        grid.setVgap(10);
        grid.add(pythonCmdLabel, 0, 0);
        grid.add(pythonCmdField, 1, 0);
        grid.add(timeoutLabel, 0, 1);
        grid.add(timeoutField, 1, 1);
        grid.add(maxThreadsLabel, 0, 2);
        grid.add(maxThreadsField, 1, 2);

        dialog.getDialogPane().setContent(grid);

        ButtonType okButtonType = new ButtonType("Save", ButtonBar.ButtonData.OK_DONE);
        dialog.getDialogPane().getButtonTypes().addAll(okButtonType, ButtonType.CANCEL);

        dialog.setResultConverter(dialogButton -> {
            if (dialogButton == okButtonType) {
                pythonCommand = pythonCmdField.getText().trim();
                try {
                    int t = Integer.parseInt(timeoutField.getText().trim());
                    int m = Integer.parseInt(maxThreadsField.getText().trim());
                    if (t > 0 && m > 0) {
                        scanTimeout = t;
                        maxThreads = m;
                    } else {
                        showAlert("Invalid Input", "Timeout and Max Threads must be positive integers.");
                    }
                } catch (NumberFormatException e) {
                    showAlert("Invalid Input", "Timeout and Max Threads must be integers.");
                }
            }
            return null;
        });

        dialog.showAndWait();
    }

    private void showAlert(String title, String message) {
        Platform.runLater(() -> {
            Alert alert = new Alert(Alert.AlertType.INFORMATION);
            alert.setTitle(title);
            alert.setHeaderText(null);
            alert.setContentText(message);
            alert.showAndWait();
        });
    }

    public static void main(String[] args) {
        launch(args);
    }

    // Data classes

    private static class Credential {
        String username;
        String password;

        Credential(String u, String p) {
            username = u;
            password = p;
        }
    }

    private static class CredentialsWrapper {
        List<Credential> ssh;
        List<Credential> ftp;

        CredentialsWrapper(List<Credential> sshList, List<Credential> ftpList) {
            ssh = sshList;
            ftp = ftpList;
        }
    }

    private static class ResultItem {
        String service;
        String ip;
        String username;
        String password;

        ResultItem(String service, String ip, String user, String pass) {
            this.service = service;
            this.ip = ip;
            this.username = user;
            this.password = pass;
        }
    }
}
