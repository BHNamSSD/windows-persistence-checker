package analyzer;

import model.PersistenceEntry;
import model.RiskLevel;

import java.nio.file.Files;
import java.nio.file.Path;

public class RiskAnalyzer {

    public void analyze(PersistenceEntry entry) {

        int score = 0;

        String path =
                entry.getPath() == null
                        ? ""
                        : entry.getPath().toLowerCase();

        String command =
                entry.getCommand() == null
                        ? ""
                        : entry.getCommand().toLowerCase();

        String name =
                entry.getName() == null
                        ? ""
                        : entry.getName().toLowerCase();

        // Suspicious locations

        if (path.contains("\\users\\public\\")) {

            score += 20;

            entry.addReason(
                    "Executable in Users\\Public"
            );
        }

        if (path.contains("\\appdata\\local\\temp\\")) {

            score += 25;

            entry.addReason(
                    "Executable in Temp directory"
            );
        }

        if (path.contains("\\windows\\temp\\")) {

            score += 25;

            entry.addReason(
                    "Executable in Windows Temp"
            );
        }

        // PowerShell

        if (command.contains("powershell")) {

            score += 15;

            entry.addReason(
                    "PowerShell execution"
            );
        }

        // Encoded PowerShell

        if (command.contains("-encodedcommand")) {

            score += 30;

            entry.addReason(
                    "Encoded PowerShell command"
            );
        }

        // Hidden PowerShell

        if (command.contains("-windowstyle hidden")) {

            score += 20;

            entry.addReason(
                    "Hidden PowerShell window"
            );
        }

        // Suspicious names

        String[] suspiciousNames = {
                "windowsupdate",
                "securityupdate",
                "systemupdate",
                "microsoftupdate",
                "chromeupdate"
        };

        for (String suspicious : suspiciousNames) {

            if (name.contains(suspicious)) {

                score += 10;

                entry.addReason(
                        "Potentially misleading system name"
                );

                break;
            }
        }

        // Check whether file exists

        if (!path.isBlank()) {

            try {

                if (!Files.exists(Path.of(path))) {

                    score += 10;

                    entry.addReason(
                            "Referenced executable does not exist"
                    );
                }

            } catch (Exception ignored) {
            }
        }

        // Cap score

        score = Math.min(score, 100);

        entry.setRiskScore(score);
        entry.setRiskLevel(calculateLevel(score));
    }

    private RiskLevel calculateLevel(int score) {

        if (score >= 80) {
            return RiskLevel.CRITICAL;
        }

        if (score >= 60) {
            return RiskLevel.HIGH;
        }

        if (score >= 30) {
            return RiskLevel.MEDIUM;
        }

        return RiskLevel.LOW;
    }
}