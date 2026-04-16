using System;

namespace AssetGuard.Models
{
    public class Item
    {
        public string Id { get; set; } = string.Empty;
        public string Detail { get; set; } = string.Empty;
        public DateTime LastModified { get; set; }
        // 0 = Synced, 1 = LocalOnly, 2 = Modified
        public int SyncState { get; set; } = 0;

        public string SyncStatusText => SyncState switch
        {
            1 => "Local",
            2 => "Modified",
            _ => "Synced",
        };
    }
}
