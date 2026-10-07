package scanner;

import model.PersistenceEntry;

import java.util.List;

public interface PersistenceScanner {

    List<PersistenceEntry> scan();
}