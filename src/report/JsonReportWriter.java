
package report;

import model.PersistenceEntry;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

public class JsonReportWriter {

    private static final DateTimeFormatter FILE_TIME =
            DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss");

    private static final DateTimeFormatter ISO_TIME =
            DateTimeFormatter.ISO_LOCAL_DATE_TIME;

    public Path writeReport(List<PersistenceEntry> entries)
            throws IOException {

        Path reportDir = Path.of("reports");
        Files.createDirectories(reportDir);

        LocalDateTime now = LocalDateTime.now();

        String filename = "persistence-report-"
                + now.format(FILE_TIME) + ".json";

        Path output = reportDir.resolve(filename);

        long registryCount = count(entries, "REGISTRY_RUN");
        long startupCount = count(entries, "STARTUP_FOLDER");
        long taskCount = count(entries, "SCHEDULED_TASK");
        long suspiciousCount = entries.stream()
                .filter(e -> e.getRiskScore() >= 30)
                .count();

        StringBuilder json = new StringBuilder();

        json.append("{\n");
        json.append("  \"tool\": \"Windows Persistence Checker\",\n");
        json.append("  \"version\": \"0.1 MVP\",\n");
        json.append("  \"scanTime\": ")
                .append(quote(now.format(ISO_TIME))).append(",\n");

        json.append("  \"summary\": {\n");
        json.append("    \"totalEntries\": ")
                .append(entries.size()).append(",\n");
        json.append("    \"registryEntries\": ")
                .append(registryCount).append(",\n");
        json.append("    \"startupEntries\": ")
                .append(startupCount).append(",\n");
        json.append("    \"scheduledTaskEntries\": ")
                .append(taskCount).append(",\n");
        json.append("    \"suspiciousEntries\": ")
                .append(suspiciousCount).append("\n");
        json.append("  },\n");

        json.append("  \"entries\": [\n");

        for (int i = 0; i < entries.size(); i++) {
            PersistenceEntry entry = entries.get(i);

            json.append("    {\n");
            json.append("      \"type\": ")
                    .append(quote(entry.getType().toString()))
                    .append(",\n");
            json.append("      \"name\": ")
                    .append(quote(entry.getName())).append(",\n");
            json.append("      \"path\": ")
                    .append(quote(entry.getPath())).append(",\n");
            json.append("      \"command\": ")
                    .append(quote(entry.getCommand())).append(",\n");
            json.append("      \"location\": ")
                    .append(quote(entry.getLocation())).append(",\n");
            json.append("      \"riskScore\": ")
                    .append(entry.getRiskScore()).append(",\n");

            json.append("      \"riskLevel\": ")
                    .append(entry.getRiskLevel() == null
                            ? "null"
                            : quote(entry.getRiskLevel().toString()))
                    .append(",\n");

            json.append("      \"reasons\": [");

            List<String> reasons = entry.getReasons();

            for (int j = 0; j < reasons.size(); j++) {
                if (j > 0) {
                    json.append(", ");
                }

                json.append(quote(reasons.get(j)));
            }

            json.append("]\n");
            json.append("    }");

            if (i < entries.size() - 1) {
                json.append(",");
            }

            json.append("\n");
        }

        json.append("  ]\n");
        json.append("}\n");

        Files.writeString(
                output,
                json.toString(),
                StandardCharsets.UTF_8
        );

        return output;
    }

    private long count(List<PersistenceEntry> entries, String type) {
        return entries.stream()
                .filter(e -> e.getType().toString().equals(type))
                .count();
    }

    private String quote(String value) {
        if (value == null) {
            return "null";
        }

        StringBuilder result = new StringBuilder("\"");

        for (char c : value.toCharArray()) {
            switch (c) {
                case '"' -> result.append("\\\"");
                case '\\' -> result.append("\\\\");
                case '\b' -> result.append("\\b");
                case '\f' -> result.append("\\f");
                case '\n' -> result.append("\\n");
                case '\r' -> result.append("\\r");
                case '\t' -> result.append("\\t");
                default -> {
                    if (c < 0x20) {
                        result.append(String.format("\\u%04x", (int) c));
                    } else {
                        result.append(c);
                    }
                }
            }
        }

        return result.append('"').toString();
    }
}
