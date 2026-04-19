using AssetGuard.Models;
using AssetGuard.Services;
using System.Collections.ObjectModel;
using System.Security.Cryptography;

namespace AssetGuard
{
    public partial class MainPage : ContentPage
    {
        private readonly ItemRepository itemRepository;
        private readonly LogService logService;
        private readonly ApiService apiService;
        private static readonly string DbPath = Path.Combine(FileSystem.AppDataDirectory, "items.db");
        private const string ApiBaseUrl = "https://example.com/api"; 
        private const string KeyIsOnline = "pref_is_online";

        public ObservableCollection<Item> Items { get; } = new();

        public bool isOnline = false;
        public bool isAuthenticated = false;

        private string latestSyncError = string.Empty;

        private Item? selectedItem;
        public Item? SelectedItem
        {
            get => selectedItem;
            set
            {
                if (selectedItem != value)
                {
                    selectedItem = value;
                    OnPropertyChanged(nameof(SelectedItem));
                }
            }
        }

        private readonly Entry? usernameEntry;
        private readonly Entry? passwordEntry;
        private readonly Grid? mainGrid;
        private readonly Grid? loginGrid;

        private readonly Switch? onlineSwitch;
        private readonly Label? onlineStatusLabel;
        private readonly ActivityIndicator? syncActivity;
        private readonly Label? syncStatusLabel;
        private readonly Entry? itemEditor;

        private const string KeyUsername = "cred_username";
        private const string KeyPasswordHash = "cred_password_hash";
        private const string KeySalt = "cred_salt";

        public MainPage()
        {
            SQLitePCL.Batteries.Init();
            InitializeComponent();
            BindingContext = this;

            usernameEntry = this.FindByName<Entry>("UsernameEntry");
            passwordEntry = this.FindByName<Entry>("PasswordEntry");
            mainGrid = this.FindByName<Grid>("MainGrid");
            loginGrid = this.FindByName<Grid>("LoginGrid");

            onlineSwitch = this.FindByName<Switch>("OnlineSwitch");
            onlineStatusLabel = this.FindByName<Label>("OnlineStatusLabel");
            syncActivity = this.FindByName<ActivityIndicator>("SyncActivity");
            syncStatusLabel = this.FindByName<Label>("SyncStatusLabel");
            itemEditor = this.FindByName<Entry>("ItemEditor");

            var tableName = "Items";
            var logFilePath = Path.Combine(FileSystem.AppDataDirectory, "useractions.log");

            itemRepository = new ItemRepository(DbPath, tableName);
            logService = new LogService(logFilePath);
            apiService = new ApiService(ApiBaseUrl);

            _ = InitializeAsync();
            _ = MainPage.EnsureDefaultCredentialsAsync();
        }

        private void RefreshLocalItems()
        {
            var local = itemRepository.LoadItems();
            Microsoft.Maui.Controls.Application.Current.Dispatcher.Dispatch(() =>
            {
                Items.Clear();
                foreach (var it in local)
                {
                    it.SyncState = isOnline ? 0 : 1;
                    Items.Add(it);
                }
            });
        }

        public async Task InitializeAsync()
        {
            try
            {
                var list = itemRepository.LoadItems();
                var val = await SecureStorage.GetAsync(KeyIsOnline);
                isOnline = val == "1";

                Microsoft.Maui.Controls.Application.Current.Dispatcher.Dispatch(() =>
                {
                    if (onlineSwitch != null) onlineSwitch.IsToggled = isOnline;
                    if (onlineStatusLabel != null) onlineStatusLabel.Text = isOnline ? "Online" : "Offline";
                });

                if (isOnline)
                {
                    await SyncWithServerAsync();
                }
                else
                {
                    Microsoft.Maui.Controls.Application.Current.Dispatcher.Dispatch(() =>
                    {
                        Items.Clear();
                        foreach (var it in list)
                        {
                            it.SyncState = 1;
                            Items.Add(it);
                        }
                    });
                }
            }
            catch (Exception)
            {
                var list = itemRepository.LoadItems();
                Microsoft.Maui.Controls.Application.Current.Dispatcher.Dispatch(() =>
                {
                    Items.Clear();
                    foreach (var it in list)
                    {
                        it.SyncState = 1;
                        Items.Add(it);
                    }
                });
            }
        }

        #region Item Management Methods (Wrappers for XAML)

        // XAML Button clicks this
        public void OnAddButtonClicked(object? sender, EventArgs e) => _ = OnAddButtonClickedAsync(sender, e);

        // Your Test calls this
        public async Task OnAddButtonClickedAsync(object? sender, EventArgs e)
        {
            try
            {
                if (!string.IsNullOrWhiteSpace(itemEditor?.Text))
                {
                    itemRepository.AddItem(itemEditor.Text);
                    var list = itemRepository.LoadItems();
                    Items.Clear();
                    foreach (var it in list)
                    {
                        it.SyncState = 1;
                        Items.Add(it);
                    }
                    logService.LogAction($"User added item: '{itemEditor.Text}'");
                    itemEditor.Text = string.Empty;
                }
            }
            catch (Exception ex)
            {
                await DisplayAlert("Error", $"Add failed: {ex.Message}", "OK");
            }
        }

        public void OnRemoveButtonClicked(object? sender, EventArgs e) => _ = OnRemoveButtonClickedAsync(sender, e);

        public async Task OnRemoveButtonClickedAsync(object? sender, EventArgs e)
        {
            try
            {
                var itemToRemove = SelectedItem;
                if (itemToRemove != null)
                {
                    itemRepository.RemoveItem(itemToRemove.Id);
                    Items.Clear();
                    foreach (var item in itemRepository.LoadItems())
                    {
                        item.SyncState = 1;
                        Items.Add(item);
                    }
                    logService.LogAction($"User removed item: '{itemToRemove.Detail}'");
                    SelectedItem = null;
                }
            }
            catch (Exception ex)
            {
                await DisplayAlert("Error", $"Remove failed: {ex.Message}", "OK");
            }
        }

        public void OnEditButtonClicked(object? sender, EventArgs e) => _ = OnEditButtonClickedAsync(sender, e);

        public async Task OnEditButtonClickedAsync(object? sender, EventArgs e)
        {
            try
            {
                var itemToEdit = SelectedItem;
                var newText = itemEditor?.Text;
                if (itemToEdit != null && !string.IsNullOrWhiteSpace(newText))
                {
                    itemRepository.EditItem(itemToEdit.Id, newText);
                    Items.Clear();
                    foreach (var item in itemRepository.LoadItems())
                    {
                        item.SyncState = 1;
                        Items.Add(item);
                    }
                    logService.LogAction($"User edited item: '{newText}'");
                    SelectedItem = null;
                    itemEditor.Text = string.Empty;
                }
            }
            catch (Exception ex)
            {
                await DisplayAlert("Error", $"Edit failed: {ex.Message}", "OK");
            }
        }
        #endregion

        #region Login/Logout Handling

        // XAML Sees this (fixes MAUIX2014)
        public async void OnLoginClicked(object sender, EventArgs e) 
        {
         _= OnLoginClickedAsync(sender, e);
        }
        // Test1.cs Sees this (fixes "Cannot await void")
        public async Task OnLoginClickedAsync(object sender, EventArgs e)
        {
            try
            {
                var username = usernameEntry?.Text ?? string.Empty;
                var password = passwordEntry?.Text ?? string.Empty;

                var verified = await VerifyCredentialsAsync(username, password);
                if (verified)
                {
                    if (loginGrid != null) loginGrid.IsVisible = false;
                    if (mainGrid != null) mainGrid.IsVisible = true;

                    isAuthenticated = true;
                    logService.LogAction($"User '{username}' logged in.");

                    Microsoft.Maui.Controls.Application.Current.Dispatcher.Dispatch(() =>
                    {
                        if (onlineSwitch != null) onlineSwitch.IsEnabled = true;
                    });

                    RefreshLocalItems();
                    if (onlineSwitch?.IsToggled == true) await SyncWithServerAsync();
                }
                else
                {
                    await DisplayAlert("Error", "Invalid username or password.", "OK");
                }
            }
            catch (Exception ex)
            {
                await DisplayAlert("Error", $"Login failed: {ex.Message}", "OK");
            }
        }

        public void OnLogoutClicked(object? sender, EventArgs e)
        {
            if (loginGrid != null) loginGrid.IsVisible = true;
            if (mainGrid != null) mainGrid.IsVisible = false;

            if (usernameEntry != null) usernameEntry.Text = string.Empty;
            if (passwordEntry != null) passwordEntry.Text = string.Empty;

            isAuthenticated = false;
            isOnline = false;

            Microsoft.Maui.Controls.Application.Current.Dispatcher.Dispatch(() =>
            {
                if (onlineSwitch != null)
                {
                    onlineSwitch.IsToggled = false;
                    onlineSwitch.IsEnabled = true;
                }
                if (onlineStatusLabel != null) onlineStatusLabel.Text = "Offline";
            });

            _ = SecureStorage.SetAsync(KeyIsOnline, "0");
        }
        #endregion

        #region Helpers and Sync
        public void OnOnlineToggled(object sender, ToggledEventArgs e)
        {
            if (onlineStatusLabel != null) onlineStatusLabel.Text = e.Value ? "Online" : "Offline";
            _ = SecureStorage.SetAsync(KeyIsOnline, e.Value ? "1" : "0");
            isOnline = e.Value;

            RefreshLocalItems();
            if (e.Value) _ = SyncWithServerAsync();
        }

        public async Task SyncWithServerAsync()
        {
            if (syncActivity?.IsRunning == true) return;

            try
            {
                var localItems = itemRepository.LoadItems();
                Microsoft.Maui.Controls.Application.Current.Dispatcher.Dispatch(() =>
                {
                    if (syncActivity != null) { syncActivity.IsVisible = true; syncActivity.IsRunning = true; }
                    if (syncStatusLabel != null) syncStatusLabel.Text = "Syncing...";
                });

                if (!isAuthenticated)
                {
                    logService.LogAction("Sync skipped: user not authenticated.");
                    Microsoft.Maui.Controls.Application.Current.Dispatcher.Dispatch(() =>
                    {
                        Items.Clear();
                        foreach (var it in localItems) { it.SyncState = 1; Items.Add(it); }
                        if (syncStatusLabel != null) syncStatusLabel.Text = "Offline";
                    });
                    return;
                }

                bool pushSucceeded = await apiService.PushItemsAsync(localItems);
                if (!pushSucceeded) throw new Exception("Server push failed.");

                var serverItems = await apiService.GetItemsAsync();
                if (serverItems == null) throw new Exception("Server fetch failed.");

                // Simplified Merge Logic
                var merged = new Dictionary<string, Item>(StringComparer.OrdinalIgnoreCase);
                foreach (var it in localItems) merged[it.Id] = it;
                foreach (var sit in serverItems) merged[sit.Id] = sit;

                var mergedList = merged.Values.OrderBy(i => i.LastModified).ToList();
                itemRepository.ReplaceAll(mergedList);

                Microsoft.Maui.Controls.Application.Current.Dispatcher.Dispatch(() =>
                {
                    Items.Clear();
                    foreach (var it in mergedList) Items.Add(it);
                    if (syncActivity != null) { syncActivity.IsRunning = false; syncActivity.IsVisible = false; }
                    if (syncStatusLabel != null) syncStatusLabel.Text = "";
                });
            }
            catch (Exception ex)
            {
                logService.LogAction($"Sync failed: {ex.Message}");
                Microsoft.Maui.Controls.Application.Current.Dispatcher.Dispatch(() =>
                {
                    if (syncActivity != null) { syncActivity.IsRunning = false; syncActivity.IsVisible = false; }
                    if (syncStatusLabel != null) syncStatusLabel.Text = "Sync failed";
                });
            }
        }

        private async void OnLogFileTapped(object? sender, TappedEventArgs e)
        {
            if (File.Exists(logService.LogFilePath))
                await Launcher.Default.OpenAsync(new OpenFileRequest { File = new ReadOnlyFile(logService.LogFilePath) });
        }

        private static async Task EnsureDefaultCredentialsAsync()
        {
            var existing = await SecureStorage.GetAsync(KeyUsername);
            if (string.IsNullOrEmpty(existing)) await CreateStoredCredentialsAsync("admin", "password123");
        }

        private static async Task CreateStoredCredentialsAsync(string username, string password)
        {
            var salt = RandomNumberGenerator.GetBytes(16);
            var hash = HashPassword(password, salt);
            await SecureStorage.SetAsync(KeyUsername, username);
            await SecureStorage.SetAsync(KeyPasswordHash, Convert.ToBase64String(hash));
            await SecureStorage.SetAsync(KeySalt, Convert.ToBase64String(salt));
        }

        private static async Task<bool> VerifyCredentialsAsync(string username, string password)
        {
            try
            {
                var storedUser = await SecureStorage.GetAsync(KeyUsername);
                if (string.IsNullOrEmpty(storedUser) || !storedUser.Equals(username, StringComparison.OrdinalIgnoreCase)) return false;

                var storedHashB64 = await SecureStorage.GetAsync(KeyPasswordHash);
                var storedSaltB64 = await SecureStorage.GetAsync(KeySalt);
                if (storedHashB64 == null || storedSaltB64 == null) return false;

                var salt = Convert.FromBase64String(storedSaltB64);
                var expectedHash = Convert.FromBase64String(storedHashB64);
                var computedHash = HashPassword(password, salt);

                return CryptographicOperations.FixedTimeEquals(computedHash, expectedHash);
            }
            catch { return false; }
        }

        private static byte[] HashPassword(string password, byte[] salt)
        {
            // Use the version that returns the byte array directly
            return Rfc2898DeriveBytes.Pbkdf2(
                password: password,
                salt: salt,
                iterations: 100_000,
                hashAlgorithm: HashAlgorithmName.SHA256,
                outputLength: 32); // Specify the length here instead of a buffer
        }
        #endregion
    }
}