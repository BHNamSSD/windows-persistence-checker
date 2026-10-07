package scanner;

import model.PersistenceEntry;
import model.PersistenceType;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

public class RegistryScanner implements PersistenceScanner {

    private static final String[] KEYS = {
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
    };

    @Override
    public List<PersistenceEntry> scan() {

        List<PersistenceEntry> results = new ArrayList<>();

        for (String key : KEYS) {
            scanKey(key, results);
        }

        return results;
    }

    private void scanKey(
            String key,
            List<PersistenceEntry> results
    ) {

        try {

            Process process = new ProcessBuilder(
                    "reg",
                    "query",
                    key
            )
                    .redirectErrorStream(true)
                    .start();

            try (BufferedReader reader =
                         new BufferedReader(
                                 new InputStreamReader(process.getInputStream())
                         )) {

                String line;

                while ((line = reader.readLine()) != null) {

                    line = line.trim();

                    if (line.isEmpty()
                            || line.startsWith("HKEY")) {
                        continue;
                    }

                    String[] parts = line.split("\\s{2,}");

                    if (parts.length < 3) {
                        continue;
                    }

                    String name = parts[0];
                    String value = parts[2];

                    PersistenceEntry entry =
                            new PersistenceEntry(
                                    PersistenceType.REGISTRY_RUN,
                                    name,
                                    extractPath(value),
                                    value,
                                    key
                            );

                    results.add(entry);
                }
            }

            process.waitFor();

        } catch (Exception e) {

            System.err.println(
                    "[ERROR] Registry scan failed: " + key
            );
        }
    }

    private String extractPath(String value) {

        value = value.trim();

        if (value.startsWith("\"")) {

            int end = value.indexOf("\"", 1);

            if (end > 0) {
                return value.substring(1, end);
            }
        }

        int exeIndex =
                value.toLowerCase().indexOf(".exe");

        if (exeIndex >= 0) {
            return value.substring(0, exeIndex + 4);
        }

        return value;
    }
}