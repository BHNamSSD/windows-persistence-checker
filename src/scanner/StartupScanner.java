package scanner;

import model.PersistenceEntry;
import model.PersistenceType;

import java.io.IOException;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.List;

public class StartupScanner implements PersistenceScanner {

    @Override
    public List<PersistenceEntry> scan() {

        List<PersistenceEntry> results = new ArrayList<>();

        String appData =
                System.getenv("APPDATA");

        String programData =
                System.getenv("PROGRAMDATA");

        if (appData != null) {

            Path startup = Paths.get(
                    appData,
                    "Microsoft",
                    "Windows",
                    "Start Menu",
                    "Programs",
                    "Startup"
            );

            scanDirectory(startup, results);
        }

        if (programData != null) {

            Path startup = Paths.get(
                    programData,
                    "Microsoft",
                    "Windows",
                    "Start Menu",
                    "Programs",
                    "StartUp"
            );

            scanDirectory(startup, results);
        }

        return results;
    }

    private void scanDirectory(
            Path directory,
            List<PersistenceEntry> results
    ) {

        if (!Files.exists(directory)) {
            return;
        }

        try (DirectoryStream<Path> stream =
                     Files.newDirectoryStream(directory)) {

            for (Path file : stream) {

                if (!Files.isRegularFile(file)) {
                    continue;
                }

                PersistenceEntry entry =
                        new PersistenceEntry(
                                PersistenceType.STARTUP_FOLDER,
                                file.getFileName().toString(),
                                file.toString(),
                                file.toString(),
                                directory.toString()
                        );

                results.add(entry);
            }

        } catch (IOException e) {

            System.err.println(
                    "[ERROR] Startup scan failed: "
                            + directory
            );
        }
    }
}