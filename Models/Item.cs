using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace AssetGuard.Models
{
    public class Item : INotifyPropertyChanged
    {
        public string Id { get; set; } = string.Empty;
        public string Detail { get; set; } = string.Empty;
        public DateTime LastModified { get; set; }

        private int _syncState;
        public int SyncState
        {
            get => _syncState;
            set
            {
                if (_syncState != value)
                {
                    _syncState = value;
                    OnPropertyChanged();
                    OnPropertyChanged(nameof(SyncStatusText)); // Updates the label text
                }
            }
        }

        //  bind to for the "Local/Synced" label
        public string SyncStatusText => SyncState == 0 ? "Synced" : "Local";

        public event PropertyChangedEventHandler? PropertyChanged;
        protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}