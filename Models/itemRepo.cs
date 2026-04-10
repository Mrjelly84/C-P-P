using Microsoft.Data.Sqlite;
using Microsoft.Maui.Storage;
using System.Collections.ObjectModel;

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
            command.CommandText =
                $"CREATE TABLE IF NOT EXISTS {tableName} (Id INTEGER PRIMARY KEY AUTOINCREMENT, Detail TEXT NOT NULL);";
            command.ExecuteNonQuery();
        }

        public ObservableCollection<string> LoadItems()
        {
            var items = new ObservableCollection<string>();
            using var connection = new SqliteConnection($"Data Source={dbPath}");
            connection.Open();
            var command = connection.CreateCommand();
            command.CommandText = $"SELECT Detail FROM {tableName};";
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                items.Add(reader.GetString(0));
            }
            return items;
        }

        public void AddItem(string detail)
        {
            using var connection = new SqliteConnection($"Data Source={dbPath}");
            connection.Open();
            var command = connection.CreateCommand();
            command.CommandText = $"INSERT INTO {tableName} (Detail) VALUES (@detail);";
            command.Parameters.AddWithValue("@detail", detail);
            command.ExecuteNonQuery();
        }

        public void RemoveItem(string detail)
        {
            using var connection = new SqliteConnection($"Data Source={dbPath}");
            connection.Open();
            var command = connection.CreateCommand();
            command.CommandText = $"DELETE FROM {tableName} WHERE Detail = @detail;";
            command.Parameters.AddWithValue("@detail", detail);
            command.ExecuteNonQuery();
        }

        public void EditItem(string oldDetail, string newDetail)
        {
            using var connection = new SqliteConnection($"Data Source={dbPath}");
            connection.Open();
            var command = connection.CreateCommand();
            command.CommandText = $"UPDATE {tableName} SET Detail = @newDetail WHERE Detail = @oldDetail;";
            command.Parameters.AddWithValue("@newDetail", newDetail);
            command.Parameters.AddWithValue("@oldDetail", oldDetail);
            command.ExecuteNonQuery();
        }
    }
}