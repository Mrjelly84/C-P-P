using Microsoft.Data.Sqlite;
using System.Collections.ObjectModel;
using System.Data;
            

namespace AssetGuard.Models
{
    public class ItemRepository
    {
        private readonly string dbPath;
        private readonly string tableName;

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
            using var connection = new SqliteConnection($"Data Source={dbPath}");
            connection.Open();
            var command = connection.CreateCommand();
            // Updated schema: Id (TEXT), Detail (TEXT), LastModified (INTEGER ticks)
            command.CommandText =
                $"CREATE TABLE IF NOT EXISTS {tableName} (Id TEXT PRIMARY KEY, Detail TEXT NOT NULL, LastModified INTEGER NOT NULL);";
            command.ExecuteNonQuery();

            // Migration: if an old table existed with only Detail column (no LastModified), try to migrate
            // We check for a column count; if mismatch, create a temp table and migrate values
            var pragma = connection.CreateCommand();
            pragma.CommandText = $"PRAGMA table_info({tableName});";
            using var reader = pragma.ExecuteReader();
            var cols = new List<string>();
            var colTypes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            while (reader.Read())
            {
                var name = reader.GetString(1);
                cols.Add(name);
                // PRAGMA table_info returns: cid, name, type, notnull, dflt_value, pk
                var type = reader.IsDBNull(2) ? string.Empty : reader.GetString(2);
                colTypes[name] = type ?? string.Empty;
            }

            bool hasLastModified = cols.Exists(c => string.Equals(c, "LastModified", StringComparison.OrdinalIgnoreCase));
            bool hasId = cols.Exists(c => string.Equals(c, "Id", StringComparison.OrdinalIgnoreCase));
            bool hasDetail = cols.Exists(c => string.Equals(c, "Detail", StringComparison.OrdinalIgnoreCase));

            // legacy single-column migration (existing logic)
            if (cols.Count == 1 && hasDetail && !hasId)
            {
                var tmp = connection.CreateCommand();
                tmp.CommandText = $"ALTER TABLE {tableName} RENAME TO {tableName}_old;";
                tmp.ExecuteNonQuery();

                var create = connection.CreateCommand();
                create.CommandText =
                    $"CREATE TABLE {tableName} (Id TEXT PRIMARY KEY, Detail TEXT NOT NULL, LastModified INTEGER NOT NULL);";
                create.ExecuteNonQuery();

                var copy = connection.CreateCommand();
                copy.CommandText = $"INSERT INTO {tableName} (Id, Detail, LastModified) SELECT lower(hex(randomblob(16))), Detail, {DateTime.UtcNow.Ticks} FROM {tableName}_old;";
                copy.ExecuteNonQuery();

                var drop = connection.CreateCommand();
                drop.CommandText = $"DROP TABLE {tableName}_old;";
                drop.ExecuteNonQuery();
            }
            // If Id exists but is not TEXT affinity, recreate table and cast Ids to TEXT
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
            // If LastModified column missing but Detail exists, add column and populate
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
            // If LastModified exists but has non-integer affinity, recreate table with correct schema and copy/convert values
            else if (hasLastModified && colTypes.TryGetValue("LastModified", out var lmType) && !string.Equals(lmType, "INTEGER", StringComparison.OrdinalIgnoreCase))
            {
                var tmp = connection.CreateCommand();
                tmp.CommandText = $"ALTER TABLE {tableName} RENAME TO {tableName}_old;";
                tmp.ExecuteNonQuery();

                var create = connection.CreateCommand();
                create.CommandText = $"CREATE TABLE {tableName} (Id TEXT PRIMARY KEY, Detail TEXT NOT NULL, LastModified INTEGER NOT NULL);";
                create.ExecuteNonQuery();

                var copy = connection.CreateCommand();
                // Convert numeric-text LastModified to integer ticks where possible; otherwise use current ticks
                copy.CommandText =
                    $"INSERT INTO {tableName} (Id, Detail, LastModified) SELECT Id, Detail, CASE WHEN typeof(LastModified) = 'integer' THEN LastModified WHEN typeof(LastModified) = 'text' AND LastModified GLOB '[0-9]*' THEN CAST(LastModified AS INTEGER) ELSE @ticks END FROM {tableName}_old;";
                copy.Parameters.AddWithValue("@ticks", DateTime.UtcNow.Ticks);
                copy.ExecuteNonQuery();

                var drop = connection.CreateCommand();
                drop.CommandText = $"DROP TABLE {tableName}_old;";
                drop.ExecuteNonQuery();
            }
        }

        public ObservableCollection<Item> LoadItems()
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

        // Replace all items in the table with the provided collection of Item.
        public void ReplaceAll(IEnumerable<Item> details)
        {
            using var connection = new SqliteConnection($"Data Source={dbPath}");
            connection.Open();
            using var transaction = connection.BeginTransaction();

            var deleteCmd = connection.CreateCommand();
            deleteCmd.CommandText = $"DELETE FROM {tableName};";
            deleteCmd.ExecuteNonQuery();

            var insertCmd = connection.CreateCommand();
            insertCmd.CommandText = $"INSERT INTO {tableName} (Id, Detail, LastModified) VALUES (@id, @detail, @lm);";
            var idParam = insertCmd.CreateParameter();
            idParam.ParameterName = "@id";
            idParam.DbType = DbType.String;
            insertCmd.Parameters.Add(idParam);
            var detailParam = insertCmd.CreateParameter();
            detailParam.ParameterName = "@detail";
            detailParam.DbType = DbType.String;
            insertCmd.Parameters.Add(detailParam);
            var lmParam = insertCmd.CreateParameter();
            lmParam.ParameterName = "@lm";
            lmParam.DbType = DbType.Int64;
            insertCmd.Parameters.Add(lmParam);

            foreach (var d in details)
            {
                idParam.Value = string.IsNullOrEmpty(d.Id) ? Guid.NewGuid().ToString() : d.Id;
                detailParam.Value = d.Detail ?? string.Empty;
                lmParam.Value = d.LastModified.Ticks;
                insertCmd.ExecuteNonQuery();
            }

            transaction.Commit();
        }

        public void AddItem(string detail)
        {
            var item = new Item { Id = Guid.NewGuid().ToString(), Detail = detail, LastModified = DateTime.UtcNow };
            using var connection = new SqliteConnection($"Data Source={dbPath}");
            connection.Open();
            var command = connection.CreateCommand();
            command.CommandText = $"INSERT INTO {tableName} (Id, Detail, LastModified) VALUES (@id, @detail, @lm);";
            var pId = command.CreateParameter();
            pId.ParameterName = "@id";
            pId.DbType = DbType.String;
            pId.Value = item.Id;
            command.Parameters.Add(pId);

            var pDetail = command.CreateParameter();
            pDetail.ParameterName = "@detail";
            pDetail.DbType = DbType.String;
            pDetail.Value = item.Detail;
            command.Parameters.Add(pDetail);

            var pLm = command.CreateParameter();
            pLm.ParameterName = "@lm";
            pLm.DbType = DbType.Int64;
            pLm.Value = item.LastModified.Ticks;
            command.Parameters.Add(pLm);

            command.ExecuteNonQuery();
            // no SyncState column in DB; in-memory tracking only
        }

        public void RemoveItem(string id)
        {
            using var connection = new SqliteConnection($"Data Source={dbPath}");
            connection.Open();
            var command = connection.CreateCommand();
            command.CommandText = $"DELETE FROM {tableName} WHERE Id = @id;";
            var p = command.CreateParameter();
            p.ParameterName = "@id";
            p.DbType = DbType.String;
            p.Value = id;
            command.Parameters.Add(p);
            command.ExecuteNonQuery();
        }

        public void EditItem(string id, string newDetail)
        {
            using var connection = new SqliteConnection($"Data Source={dbPath}");
            connection.Open();
            var command = connection.CreateCommand();
            command.CommandText = $"UPDATE {tableName} SET Detail = @newDetail, LastModified = @lm WHERE Id = @id;";
            var pNew = command.CreateParameter();
            pNew.ParameterName = "@newDetail";
            pNew.DbType = DbType.String;
            pNew.Value = newDetail;
            command.Parameters.Add(pNew);

            var pLm = command.CreateParameter();
            pLm.ParameterName = "@lm";
            pLm.DbType = DbType.Int64;
            pLm.Value = DateTime.UtcNow.Ticks;
            command.Parameters.Add(pLm);

            var pId = command.CreateParameter();
            pId.ParameterName = "@id";
            pId.DbType = DbType.String;
            pId.Value = id;
            command.Parameters.Add(pId);

            command.ExecuteNonQuery();
        }

        // Optional helper to update sync state in memory (no DB persistence here)
        public void UpdateSyncState(IEnumerable<Item> items, int state)
        {
            // No-op in repository; consumers update Item.SyncState in memory after loading
        }
    }
}