using Microsoft.Data.Sqlite;
using System.Collections.ObjectModel;

namespace AssetGuard.Models
{
    public class ItemRepository
    {
        private readonly string? dbPath;
        private readonly string? tableName;

        public ItemRepository() { }

        public ItemRepository(string dbPath, string tableName)
        {
            if (!Path.IsPathRooted(dbPath))
                dbPath = Path.Combine(FileSystem.AppDataDirectory, dbPath);

            this.dbPath = dbPath;
            this.tableName = tableName;
            InitializeDatabase();
        }

        private void InitializeDatabase()
        {
            if (string.IsNullOrEmpty(dbPath)) return;

            using var connection = new SqliteConnection($"Data Source={dbPath}");
            connection.Open();

            // 1. UPDATED SCHEMA: Added SyncState (INTEGER)
            var command = connection.CreateCommand();
            command.CommandText =
                $"CREATE TABLE IF NOT EXISTS {tableName} (Id TEXT PRIMARY KEY, Detail TEXT NOT NULL, LastModified INTEGER NOT NULL, SyncState INTEGER DEFAULT 0);";
            command.ExecuteNonQuery();

            // 2. MIGRATION CHECK: Ensure existing tables get the SyncState column
            var pragma = connection.CreateCommand();
            pragma.CommandText = $"PRAGMA table_info({tableName});";
            using var reader = pragma.ExecuteReader();
            bool hasSyncState = false;
            while (reader.Read())
            {
                if (string.Equals(reader.GetString(1), "SyncState", StringComparison.OrdinalIgnoreCase))
                    hasSyncState = true;
            }

            if (!hasSyncState)
            {
                var addCol = connection.CreateCommand();
                addCol.CommandText = $"ALTER TABLE {tableName} ADD COLUMN SyncState INTEGER DEFAULT 0;";
                addCol.ExecuteNonQuery();
            }
        }

        public virtual ObservableCollection<Item> LoadItems()
        {
            var items = new ObservableCollection<Item>();
            if (string.IsNullOrEmpty(dbPath)) return items;

            using var connection = new SqliteConnection($"Data Source={dbPath}");
            connection.Open();
            var command = connection.CreateCommand();
            // 3. UPDATED SELECT: Pull SyncState from DB
            command.CommandText = $"SELECT Id, Detail, LastModified, SyncState FROM {tableName};";

            using SqliteDataReader reader = command.ExecuteReader();
            while (reader.Read())
            {
                var id = reader.GetString(0);
                var detail = reader.GetString(1);
                var ticks = reader.GetInt64(2);
                // 4. READ ACTUAL STATE: Don't hardcode 0 anymore
                var syncState = reader.IsDBNull(3) ? 0 : reader.GetInt32(3);

                var it = new Item
                {
                    Id = id,
                    Detail = detail,
                    LastModified = new DateTime(ticks),
                    SyncState = syncState
                };
                items.Add(it);
            }
            return items;
        }

        public virtual void AddItem(string detail)
        {
            // 5. INITIAL STATE: New items should start as '1' (LocalOnly)
            var item = new Item { Id = Guid.NewGuid().ToString(), Detail = detail, LastModified = DateTime.UtcNow, SyncState = 1 };

            using var connection = new SqliteConnection($"Data Source={dbPath}");
            connection.Open();
            var command = connection.CreateCommand();
            command.CommandText = $"INSERT INTO {tableName} (Id, Detail, LastModified, SyncState) VALUES (@id, @detail, @lm, @ss);";

            command.Parameters.AddWithValue("@id", item.Id);
            command.Parameters.AddWithValue("@detail", item.Detail);
            command.Parameters.AddWithValue("@lm", item.LastModified.Ticks);
            command.Parameters.AddWithValue("@ss", item.SyncState);

            command.ExecuteNonQuery();
        }

        public virtual void EditItem(string id, string newDetail)
        {
            using var connection = new SqliteConnection($"Data Source={dbPath}");
            connection.Open();
            var command = connection.CreateCommand();
            // 6. UPDATE STATE: Mark as '2' (LocalModified) when edited
            command.CommandText = $"UPDATE {tableName} SET Detail = @newDetail, LastModified = @lm, SyncState = 2 WHERE Id = @id;";
            command.Parameters.AddWithValue("@newDetail", newDetail);
            command.Parameters.AddWithValue("@lm", DateTime.UtcNow.Ticks);
            command.Parameters.AddWithValue("@id", id);

            command.ExecuteNonQuery();
        }

        // 7. SYNC HELPER: Use this after a successful sync to update DB
        public virtual void UpdateSyncState(IEnumerable<Item> items, int state)
        {
            using var connection = new SqliteConnection($"Data Source={dbPath}");
            connection.Open();
            using var transaction = connection.BeginTransaction();

            var command = connection.CreateCommand();
            command.CommandText = $"UPDATE {tableName} SET SyncState = @state WHERE Id = @id;";
            var stateParam = command.Parameters.Add("@state", SqliteType.Integer);
            var idParam = command.Parameters.Add("@id", SqliteType.Text);

            foreach (var item in items)
            {
                stateParam.Value = state;
                idParam.Value = item.Id;
                command.ExecuteNonQuery();
                item.SyncState = state; // Update in-memory object too
            }
            transaction.Commit();
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


        public virtual void ReplaceAll(IEnumerable<Item> details)
        {
            if (string.IsNullOrEmpty(dbPath)) return;

            using var connection = new SqliteConnection($"Data Source={dbPath}");
            connection.Open();
            using var transaction = connection.BeginTransaction();

            try
            {
                var deleteCmd = connection.CreateCommand();
                deleteCmd.CommandText = $"DELETE FROM {tableName};";
                deleteCmd.ExecuteNonQuery();

                var insertCmd = connection.CreateCommand();
                // Added SyncState to the insert
                insertCmd.CommandText = $"INSERT INTO {tableName} (Id, Detail, LastModified, SyncState) VALUES (@id, @detail, @lm, @ss);";

                var pId = insertCmd.Parameters.Add("@id", SqliteType.Text);
                var pDetail = insertCmd.Parameters.Add("@detail", SqliteType.Text);
                var pLm = insertCmd.Parameters.Add("@lm", SqliteType.Integer);
                var pSs = insertCmd.Parameters.Add("@ss", SqliteType.Integer);

                foreach (var d in details)
                {
                    pId.Value = string.IsNullOrEmpty(d.Id) ? Guid.NewGuid().ToString() : d.Id;
                    pDetail.Value = d.Detail ?? string.Empty;
                    pLm.Value = d.LastModified.Ticks;
                    pSs.Value = d.SyncState; // Keep the state from the server (usually 0)
                    insertCmd.ExecuteNonQuery();
                }

                transaction.Commit();
            }
            catch
            {
                transaction.Rollback();
                throw;
            }
        }

    }
}