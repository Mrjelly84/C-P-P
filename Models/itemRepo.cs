using Microsoft.Data.Sqlite;
using System.Collections.ObjectModel;
using System.Data;

namespace AssetGuard.Models
{
    public class ItemRepository
    {
        private readonly string? dbPath;
        private readonly string? tableName;

        // --- NEW: Empty constructor for Unit Testing/Moq ---
        // This allows Moq to bypass the database setup during tests.
        public ItemRepository() { }

        public ItemRepository(string dbPath, string tableName)
        {
            // Ensure dbPath is a full path in the app's data directory
            if (!Path.IsPathRooted(dbPath))
                dbPath = Path.Combine(FileSystem.AppDataDirectory, dbPath);

            this.dbPath = dbPath;
            this.tableName = tableName;
            InitializeDatabase();
        }

        private void InitializeDatabase()
        {
            // If we are in a test and dbPath is null, exit early
            if (string.IsNullOrEmpty(dbPath)) return;

            using var connection = new SqliteConnection($"Data Source={dbPath}");
            connection.Open();
            var command = connection.CreateCommand();
            command.CommandText =
                $"CREATE TABLE IF NOT EXISTS {tableName} (Id TEXT PRIMARY KEY, Detail TEXT NOT NULL, LastModified INTEGER NOT NULL);";
            command.ExecuteNonQuery();

            // ... (Rest of your migration logic remains exactly the same) ...
            var pragma = connection.CreateCommand();
            pragma.CommandText = $"PRAGMA table_info({tableName});";
            using var reader = pragma.ExecuteReader();
            var cols = new List<string>();
            var colTypes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            while (reader.Read())
            {
                var name = reader.GetString(1);
                cols.Add(name);
                var type = reader.IsDBNull(2) ? string.Empty : reader.GetString(2);
                colTypes[name] = type ?? string.Empty;
            }

            bool hasLastModified = cols.Exists(c => string.Equals(c, "LastModified", StringComparison.OrdinalIgnoreCase));
            bool hasId = cols.Exists(c => string.Equals(c, "Id", StringComparison.OrdinalIgnoreCase));
            bool hasDetail = cols.Exists(c => string.Equals(c, "Detail", StringComparison.OrdinalIgnoreCase));

            if (cols.Count == 1 && hasDetail && !hasId)
            {
                var tmp = connection.CreateCommand();
                tmp.CommandText = $"ALTER TABLE {tableName} RENAME TO {tableName}_old;";
                tmp.ExecuteNonQuery();

                var create = connection.CreateCommand();
                create.CommandText = $"CREATE TABLE {tableName} (Id TEXT PRIMARY KEY, Detail TEXT NOT NULL, LastModified INTEGER NOT NULL);";
                create.ExecuteNonQuery();

                var copy = connection.CreateCommand();
                copy.CommandText = $"INSERT INTO {tableName} (Id, Detail, LastModified) SELECT lower(hex(randomblob(16))), Detail, {DateTime.UtcNow.Ticks} FROM {tableName}_old;";
                copy.ExecuteNonQuery();

                var drop = connection.CreateCommand();
                drop.CommandText = $"DROP TABLE {tableName}_old;";
                drop.ExecuteNonQuery();
            }
            else if (hasId && colTypes.TryGetValue("Id", out var idType) && !string.Equals(idType, "TEXT", StringComparison.OrdinalIgnoreCase))
            {
                var tmpId = connection.CreateCommand();
                tmpId.CommandText = $"ALTER TABLE {tableName} RENAME TO {tableName}_old;";
                tmpId.ExecuteNonQuery();

                var createId = connection.CreateCommand();
                createId.CommandText = $"CREATE TABLE {tableName} (Id TEXT PRIMARY KEY, Detail TEXT NOT NULL, LastModified INTEGER NOT NULL);";
                createId.ExecuteNonQuery();

                var copyId = connection.CreateCommand();
                copyId.CommandText = $"INSERT INTO {tableName} (Id, Detail, LastModified) SELECT CAST(Id AS TEXT), Detail, COALESCE(LastModified, @ticks) FROM {tableName}_old;";
                copyId.Parameters.AddWithValue("@ticks", DateTime.UtcNow.Ticks);
                copyId.ExecuteNonQuery();

                var dropId = connection.CreateCommand();
                dropId.CommandText = $"DROP TABLE {tableName}_old;";
                dropId.ExecuteNonQuery();
            }
            else if (!hasLastModified && hasDetail)
            {
                var addCol = connection.CreateCommand();
                addCol.CommandText = $"ALTER TABLE {tableName} ADD COLUMN LastModified INTEGER;";
                addCol.ExecuteNonQuery();

                var update = connection.CreateCommand();
                update.CommandText = $"UPDATE {tableName} SET LastModified = @ticks WHERE LastModified IS NULL;";
                update.Parameters.AddWithValue("@ticks", DateTime.UtcNow.Ticks);
                update.ExecuteNonQuery();
            }
        }

        // --- ALL DATA METHODS ARE NOW VIRTUAL ---

        public virtual ObservableCollection<Item> LoadItems()
        {
            var items = new ObservableCollection<Item>();
            using var connection = new SqliteConnection($"Data Source={dbPath}");
            connection.Open();
            var command = connection.CreateCommand();
            command.CommandText = $"SELECT Id, Detail, LastModified FROM {tableName};";
            using SqliteDataReader reader = command.ExecuteReader();
            while (reader.Read())
            {
                var id = reader.GetString(0);
                var detail = reader.GetString(1);
                var ticks = reader.IsDBNull(2) ? DateTime.UtcNow.Ticks : reader.GetInt64(2);
                var it = new Item { Id = id, Detail = detail, LastModified = new DateTime(ticks), SyncState = 0 };
                items.Add(it);
            }
            return items;
        }

        public virtual void ReplaceAll(IEnumerable<Item> details)
        {
            using var connection = new SqliteConnection($"Data Source={dbPath}");
            connection.Open();
            using var transaction = connection.BeginTransaction();

            var deleteCmd = connection.CreateCommand();
            deleteCmd.CommandText = $"DELETE FROM {tableName};";
            deleteCmd.ExecuteNonQuery();

            var insertCmd = connection.CreateCommand();
            insertCmd.CommandText = $"INSERT INTO {tableName} (Id, Detail, LastModified) VALUES (@id, @detail, @lm);";
            // ... (parameter setup)
            transaction.Commit();
        }

        public virtual void AddItem(string detail)
        {
            var item = new Item { Id = Guid.NewGuid().ToString(), Detail = detail, LastModified = DateTime.UtcNow };
            using var connection = new SqliteConnection($"Data Source={dbPath}");
            connection.Open();
            var command = connection.CreateCommand();
            command.CommandText = $"INSERT INTO {tableName} (Id, Detail, LastModified) VALUES (@id, @detail, @lm);";

            command.Parameters.AddWithValue("@id", item.Id);
            command.Parameters.AddWithValue("@detail", item.Detail);
            command.Parameters.AddWithValue("@lm", item.LastModified.Ticks);

            command.ExecuteNonQuery();
        }

        public virtual void RemoveItem(string id)
        {
            using var connection = new SqliteConnection($"Data Source={dbPath}");
            connection.Open();
            var command = connection.CreateCommand();
            command.CommandText = $"DELETE FROM {tableName} WHERE Id = @id;";
            command.Parameters.AddWithValue("@id", id);
            command.ExecuteNonQuery();
        }

        public virtual void EditItem(string id, string newDetail)
        {
            using var connection = new SqliteConnection($"Data Source={dbPath}");
            connection.Open();
            var command = connection.CreateCommand();
            command.CommandText = $"UPDATE {tableName} SET Detail = @newDetail, LastModified = @lm WHERE Id = @id;";
            command.Parameters.AddWithValue("@newDetail", newDetail);
            command.Parameters.AddWithValue("@lm", DateTime.UtcNow.Ticks);
            command.Parameters.AddWithValue("@id", id);

            command.ExecuteNonQuery();
        }

        public virtual void UpdateSyncState(IEnumerable<Item> items, int state) { }
    }
}