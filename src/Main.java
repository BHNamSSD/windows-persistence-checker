import analyzer.RiskAnalyzer;
import model.PersistenceEntry;
import scanner.*;

import java.util.ArrayList;
import java.util.List;

public class Main {

    public static void main(String[] args) {

        printBanner();

        List<PersistenceScanner> scanners =
                List.of(
                        new RegistryScanner(),
                        new StartupScanner(),
                        new ScheduledTaskScanner()
                );

        List<PersistenceEntry> results =
                new ArrayList<>();

        RiskAnalyzer analyzer =
                new RiskAnalyzer();

        System.out.println(
                "[*] Starting persistence scan...\n"
        );

        for (PersistenceScanner scanner : scanners) {

            System.out.println(
                    "[*] Running: "
                            + scanner.getClass()
                            .getSimpleName()
            );

            List<PersistenceEntry> entries =
                    scanner.scan();

            for (PersistenceEntry entry : entries) {

                analyzer.analyze(entry);

                results.add(entry);
            }
        }

        printResults(results);
    }

    private static void printBanner() {

        System.out.println("""
                
                ==========================================
                  Windows Persistence Checker
                  BHNamSSD
                  Version 0.1
                ==========================================
                """);
    }

    private static void printResults(
            List<PersistenceEntry> results
    ) {

        System.out.println(
                "\n=========================================="
        );

        System.out.println(
                " Persistence Findings"
        );

        System.out.println(
                "==========================================\n"
        );

        int suspicious = 0;

        for (PersistenceEntry entry : results) {

            if (entry.getRiskScore() < 30) {
                continue;
            }

            suspicious++;

            System.out.println(
                    "[SUSPICIOUS]"
            );

            System.out.println(
                    "Type: "
                            + entry.getType()
            );

            System.out.println(
                    "Name: "
                            + entry.getName()
            );

            System.out.println(
                    "Path: "
                            + entry.getPath()
            );

            System.out.println(
                    "Command: "
                            + entry.getCommand()
            );

            System.out.println(
                    "Location: "
                            + entry.getLocation()
            );

            System.out.println(
                    "Risk Score: "
                            + entry.getRiskScore()
            );

            System.out.println(
                    "Risk Level: "
                            + entry.getRiskLevel()
            );

            if (!entry.getReasons().isEmpty()) {

                System.out.println(
                        "Reasons:"
                );

                for (String reason :
                        entry.getReasons()) {

                    System.out.println(
                            "  [+] " + reason
                    );
                }
            }

            System.out.println(
                    "\n------------------------------------------\n"
            );
        }

        System.out.println(
                "Total persistence entries: "
                        + results.size()
        );

        System.out.println(
                "Suspicious entries: "
                        + suspicious
        );

        System.out.println(
                "\n[*] Scan completed."
        );
    }
}