package scanner;

import model.PersistenceEntry;
import model.PersistenceType;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

public class ScheduledTaskScanner implements PersistenceScanner {

    @Override
    public List<PersistenceEntry> scan() {

        List<PersistenceEntry> results =
                new ArrayList<>();

        try {

            Process process = new ProcessBuilder(
                    "schtasks",
                    "/query",
                    "/fo",
                    "CSV",
                    "/v"
            )
                    .redirectErrorStream(true)
                    .start();

            try (BufferedReader reader =
                         new BufferedReader(
                                 new InputStreamReader(
                                         process.getInputStream()
                                 )
                         )) {

                String line;

                boolean header = true;

                while ((line = reader.readLine()) != null) {

                    if (header) {
                        header = false;
                        continue;
                    }

                    if (line.isBlank()) {
                        continue;
                    }

                    String[] fields =
                            parseCsv(line);

                    if (fields.length < 2) {
                        continue;
                    }

                    String taskName =
                            fields[0];

                    String command =
                            findCommand(fields);

                    PersistenceEntry entry =
                            new PersistenceEntry(
                                    PersistenceType.SCHEDULED_TASK,
                                    taskName,
                                    extractExecutable(command),
                                    command,
                                    "Task Scheduler"
                            );

                    results.add(entry);
                }
            }

            process.waitFor();

        } catch (Exception e) {

            System.err.println(
                    "[ERROR] Scheduled Task scan failed"
            );
        }

        return results;
    }

    private String[] parseCsv(String line) {

        List<String> fields =
                new ArrayList<>();

        boolean quoted = false;
        StringBuilder current =
                new StringBuilder();

        for (char c : line.toCharArray()) {

            if (c == '"') {
                quoted = !quoted;
            } else if (c == ',' && !quoted) {

                fields.add(
                        current.toString().trim()
                );

                current.setLength(0);

            } else {

                current.append(c);
            }
        }

        fields.add(current.toString().trim());

        return fields.toArray(new String[0]);
    }

    private String findCommand(String[] fields) {

        for (String field : fields) {

            String lower =
                    field.toLowerCase();

            if (lower.contains(".exe")
                    || lower.contains("powershell")
                    || lower.contains("cmd.exe")
                    || lower.contains("wscript")
                    || lower.contains("cscript")) {

                return field;
            }
        }

        return "";
    }

    private String extractExecutable(String command) {

        if (command == null || command.isBlank()) {
            return "";
        }

        String value = command.trim();

        if (value.startsWith("\"")) {

            int end =
                    value.indexOf("\"", 1);

            if (end > 0) {
                return value.substring(1, end);
            }
        }

        int exe =
                value.toLowerCase()
                        .indexOf(".exe");

        if (exe >= 0) {
            return value.substring(
                    0,
                    exe + 4
            );
        }

        return value;
    }
}