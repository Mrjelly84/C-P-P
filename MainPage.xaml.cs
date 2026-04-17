using AssetGuard.Models;
using AssetGuard.Services;
using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.IO; // Added necessary using statement for Path and FileSystem
using System.Linq; // Added necessary using statement for Linq methods

namespace AssetGuard
{
    public partial class MainPage : ContentPage
    {
        private readonly ItemRepository itemRepository;
        private readonly LogService logService;
        private readonly ApiService apiService;
        private static readonly string DbPath = Path.Combine(FileSystem.AppDataDirectory, "items.db");
        private const string ApiBaseUrl = "https://example.com/api"; // replace with your real API
        private const string KeyIsOnline = "pref_is_online";

        public ObservableCollection<Item> Items { get; } = new();

        private bool isOnline = false;
        private bool isAuthenticated = false;
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

        // UI elements that are used frequently, define them as local variables for safer access
        private readonly Switch? onlineSwitch;
        private readonly Label? onlineStatusLabel;
        private readonly ActivityIndicator? syncActivity;
        private readonly Label? syncStatusLabel;
        private readonly Entry? itemEditor; // Defined here since it's used in the methods

        // Secure storage keys
        private const string KeyUsername = "cred_username";
        private const string KeyPasswordHash = "cred_password_hash";
        private const string KeySalt = "cred_salt";

        #region:MainPage
        public MainPage()
        {
            SQLitePCL.Batteries.Init();
            InitializeComponent();
            BindingContext = this;

            // Note: FindByName returns nullable types (Entry?), which is why null checks are necessary.
            usernameEntry = this.FindByName<Entry>("UsernameEntry");
            passwordEntry = this.FindByName<Entry>("PasswordEntry");
            mainGrid = this.FindByName<Grid>("MainGrid");
            loginGrid = this.FindByName<Grid>("LoginGrid");

            // Initialize other referenced UI components for safety
            onlineSwitch = this.FindByName<Switch>("OnlineSwitch");
            onlineStatusLabel = this.FindByName<Label>("OnlineStatusLabel");
            syncActivity = this.FindByName<ActivityIndicator>("SyncActivity");
            syncStatusLabel = this.FindByName<Label>("SyncStatusLabel");
            itemEditor = this.FindByName<Entry>("ItemEditor"); // Assuming this is the name

            var tableName = "Items";
            var logFilePath = Path.Combine(FileSystem.AppDataDirectory, "useractions.log");

            itemRepository = new ItemRepository(DbPath, tableName);
            logService = new LogService(logFilePath);

            apiService = new ApiService(ApiBaseUrl);

            // Defer loading and state initialization to async initializer
            _ = InitializeAsync();

            // Ensure credentials exist
            _ = MainPage.EnsureDefaultCredentialsAsync();
        }
        #endregion

        private void RefreshLocalItems()
        {
            var local = itemRepository.LoadItems();
            // Using Dispatcher.Dispatch for modern MAUI main thread access
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

        private async Task InitializeAsync()
        {
            try
            {
                var list = itemRepository.LoadItems();
                var val = await SecureStorage.GetAsync(KeyIsOnline);
                isOnline = val == "1";

                // Ensure UI switch and label reflect stored state
                Microsoft.Maui.Controls.Application.Current.Dispatcher.Dispatch(() =>
                {
                    // FIX: Use local, non-nullable variables for cleaner, safer access
                    onlineSwitch?.IsToggled = isOnline;
                    onlineStatusLabel?.Text = isOnline ? "Online" : "Offline";
                });

                if (isOnline)
                {
                    await SyncWithServerAsync();
                }
                else
                {
                    // Offline: show local items and mark them accordingly
                    Microsoft.Maui.Controls.Application.Current.Dispatcher.Dispatch(() =>
                    {
                        Items.Clear();
                        foreach (var it in list)
                        {
                            it.SyncState = 1; // local
                            Items.Add(it);
                        }
                    });
                }
            }
            catch (Exception)
            {
                // If initialization fails, fall back to showing local DB items as local
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

        #region:Methods of MainPage
        private async void OnAddButtonClicked(object? sender, EventArgs e)
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
                await DisplayAlertAsync("Error", $"Add failed: {ex.Message}", "OK");
            }
        }

        private async void OnRemoveButtonClicked(object? sender, EventArgs e)
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
                await DisplayAlertAsync("Error", $"Remove failed: {ex.Message}", "OK");
            }
        }

        private async void OnEditButtonClicked(object? sender, EventArgs e)
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
                await DisplayAlertAsync("Error", $"Edit failed: {ex.Message}", "OK");
            }
        }
        #endregion

        #region:Login/Logout and credential handling

        private async void OnLoginClicked(object? sender, EventArgs e)
        {
            try
            {
                var username = usernameEntry?.Text ?? string.Empty;
                var password = passwordEntry?.Text ?? string.Empty;

                var verified = await VerifyCredentialsAsync(username, password);
                if (verified)
                {
                    loginGrid?.IsVisible = false;
                    mainGrid?.IsVisible = true;

                    isAuthenticated = true;
                    logService.LogAction($"User '{username}' logged in.");

                    Microsoft.Maui.Controls.Application.Current.Dispatcher.Dispatch(() =>
                    {
                        // FIX: Use onlineSwitch directly
                        onlineSwitch?.IsEnabled = true;
                    });

                    RefreshLocalItems();

                    try
                    {
                        // FIX: Check if the control exists before accessing properties
                        if (onlineSwitch?.IsToggled == true)
                        {
                            await SyncWithServerAsync();
                        }
                        else
                        {
                            var val = await SecureStorage.GetAsync(KeyIsOnline);
                            if (val == "1")
                            {
                                await SyncWithServerAsync();
                            }
                        }
                    }
                    catch (Exception)
                    {
                        
                    }
                }
                else
                {
                    await DisplayAlertAsync("Error", "Invalid username or password.", "OK");
                }
            }
            catch (Exception ex)
            {
                await DisplayAlertAsync("Error", $"Login failed: {ex.Message}", "OK");
            }
        }

        private void OnLogoutClicked(object? sender, EventArgs e)
        {
            loginGrid?.IsVisible = true;
            mainGrid?.IsVisible = false;

            usernameEntry?.Text = string.Empty;
            passwordEntry?.Text = string.Empty;

            isAuthenticated = false;

            Microsoft.Maui.Controls.Application.Current.Dispatcher.Dispatch(() =>
            {
                // FIX: Use local, non-nullable variables for cleaner, safer access
                onlineSwitch?.IsToggled = false;
                onlineSwitch?.IsEnabled = true;
                onlineStatusLabel?.Text = "Offline";
            });

            _ = SecureStorage.SetAsync(KeyIsOnline, "0");
            isOnline = false;
        }

        private async void OnLogFileTapped(object? sender, Microsoft.Maui.Controls.TappedEventArgs e)
        {
            if (File.Exists(logService.LogFilePath))
            {
                await Launcher.Default.OpenAsync(new OpenFileRequest
                {
                    File = new ReadOnlyFile(logService.LogFilePath)
                });
            }
            else
            {
                await DisplayAlertAsync("Log File", "Log file not found.", "OK");
            }
        }

        private async void OnOpenMockServerClicked(object? sender, EventArgs e)
        {
            var mockPath = Path.Combine(FileSystem.AppDataDirectory, "mock_server_items.json");
            if (File.Exists(mockPath))
            {
                await Launcher.Default.OpenAsync(new OpenFileRequest { File = new ReadOnlyFile(mockPath) });
            }
            else
            {
                await DisplayAlertAsync("Mock Server", "Mock server file not found.", "OK");
            }
        }

        private async void OnCopyLogToRepoClicked(object? sender, EventArgs e)
        {
            try
            {
                var runtimePath = logService.LogFilePath;
                if (!File.Exists(runtimePath))
                {
                    await DisplayAlertAsync("Copy Log", "Runtime log not found.", "OK");
                    return;
                }

                var repoRoot = @"C:\Users\willi\source\repos\Mrjelly84\C-P-P";
                string target = Directory.Exists(repoRoot)
                    ? Path.Combine(repoRoot, "useractions_runtime_copy.log")
                    : Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "useractions_runtime_copy.log");

                File.Copy(runtimePath, target, true);
                await DisplayAlertAsync("Copy Log", $"Copied runtime log to: {target}", "OK");
            }
            catch (Exception ex)
            {
                await DisplayAlertAsync("Copy Log", $"Copy failed: {ex.Message}", "OK");
            }
        }

        private void OnOnlineToggled(object sender, ToggledEventArgs e)
        {
            // FIX: Use local, non-nullable variables for cleaner, safer access
            onlineStatusLabel?.Text = e.Value ? "Online" : "Offline";

            _ = SecureStorage.SetAsync(KeyIsOnline, e.Value ? "1" : "0");
            isOnline = e.Value;

            var localNow = itemRepository.LoadItems();
            Microsoft.Maui.Controls.Application.Current.Dispatcher.Dispatch(() =>
            {
                Items.Clear();
                foreach (var it in localNow)
                    Items.Add(it);
            });

            if (e.Value)
            {
                _ = SyncWithServerAsync();
            }
        }

        private async Task SyncWithServerAsync()
        {
            // Prevent re-entrancy during sync
            // FIX: Use local, non-nullable variables for cleaner, safer access
            if (syncActivity?.IsRunning == true)
            {
                return;
            }

            try
            {
                var localItems = itemRepository.LoadItems();

                // Start progress UI
                Microsoft.Maui.Controls.Application.Current.Dispatcher.Dispatch(() =>
                {
                    // FIX: Check if controls are initialized before setting visibility/running state
                    syncActivity?.IsVisible = true;
                    syncActivity?.IsRunning = true;
                    syncStatusLabel?.Text = "Syncing...";
                });

                // 1. Push local items
                if (!isAuthenticated)
                {
                    logService.LogAction("Sync skipped: user not authenticated.");
                    Microsoft.Maui.Controls.Application.Current.Dispatcher.Dispatch(() =>
                    {
                        Items.Clear();
                        foreach (var it in localItems)
                        {
                            it.SyncState = 1; // local only
                            Items.Add(it);
                        }
                        syncStatusLabel?.Text = "Offline";
                        onlineStatusLabel?.Text = "Offline";
                    });
                    return;
                }

                bool pushSucceeded;
                try
                {
                    pushSucceeded = await apiService.PushItemsAsync(localItems);
                }
                catch (Exception ex)
                {
                    latestSyncError = ex.Message;
                    logService.LogAction($"Sync push failed: {ex}");

                    Microsoft.Maui.Controls.Application.Current.Dispatcher.Dispatch(async () =>
                    {
                        Items.Clear();
                        foreach (var it in localItems)
                        {
                            it.SyncState = 1;
                            Items.Add(it);
                        }
                        syncStatusLabel?.Text = "Sync failed";
                        await DisplayAlertAsync("Sync Error", latestSyncError, "OK");
                    });
                    return;
                }

                if (!pushSucceeded)
                {
                    latestSyncError = "Sync push failed: server returned non-success status.";
                    logService.LogAction(latestSyncError);
                    Microsoft.Maui.Controls.Application.Current.Dispatcher.Dispatch(async () =>
                    {
                        Items.Clear();
                        foreach (var it in localItems)
                        {
                            it.SyncState = 1;
                            Items.Add(it);
                        }
                        syncStatusLabel?.Text = "Sync failed";
                        await DisplayAlertAsync("Sync Error", latestSyncError, "OK");
                    });
                    return;
                }

                // 2. Fetch server items
                var serverItems = await apiService.GetItemsAsync();
                if (serverItems == null || !serverItems.Any())
                {
                    latestSyncError = "Sync fetch returned no items: treating as sync failure.";
                    logService.LogAction(latestSyncError);

                    Microsoft.Maui.Controls.Application.Current.Dispatcher.Dispatch(async () =>
                    {
                        Items.Clear();
                        foreach (var it in localItems)
                        {
                            it.SyncState = 1;
                            Items.Add(it);
                        }
                        syncStatusLabel?.Text = "Sync failed";
                        await DisplayAlertAsync("Sync Error", latestSyncError, "OK");
                    });
                    return;
                }

                // Merge local and server items
                var merged = new Dictionary<string, Item>(StringComparer.OrdinalIgnoreCase);
                foreach (var it in localItems)
                    merged[it.Id] = it;

                foreach (var sit in serverItems)
                {
                    if (merged.TryGetValue(sit.Id, out var existing) && sit.LastModified > existing.LastModified)
                    {
                        merged[sit.Id] = sit;
                    }
                    else if (!merged.ContainsKey(sit.Id))
                    {
                        merged[sit.Id] = sit;
                    }
                }

                var mergedList = merged.Values.OrderBy(i => i.LastModified).ToList();

                // Update sync state per item
                foreach (var it in mergedList)
                {
                    it.SyncState = 0;
                }

                // Detect local-only and modified items
                var localIds = new HashSet<string>(localItems.Select(i => i.Id), StringComparer.OrdinalIgnoreCase);
                var serverIds = new HashSet<string>(serverItems.Select(i => i.Id), StringComparer.OrdinalIgnoreCase);

                foreach (var it in mergedList)
                {
                    if (localIds.Contains(it.Id) && !serverIds.Contains(it.Id))
                        it.SyncState = 1; // local only
                    else if (localIds.Contains(it.Id) && serverIds.Contains(it.Id))
                    {
                        var local = localItems.FirstOrDefault(x => x.Id == it.Id);
                        var server = serverItems.FirstOrDefault(x => x.Id == it.Id);
                        // Check if local version is newer than the server version
                        if (local != null && server != null && local.LastModified > server.LastModified)
                            it.SyncState = 2; // modified locally
                    }
                }

                // Update local DB and UI with merged collection
                itemRepository.ReplaceAll(mergedList);
                Microsoft.Maui.Controls.Application.Current.Dispatcher.Dispatch(() =>
                {
                    Items.Clear();
                    foreach (var it in mergedList)
                        Items.Add(it);
                });

                // 3. Push merged collection back to server
                await apiService.PushItemsAsync(mergedList);

                logService.LogAction("Sync completed (per-item last-write-wins).");

                // End progress UI
                Microsoft.Maui.Controls.Application.Current.Dispatcher.Dispatch(() =>
                {
                    syncActivity?.IsRunning = false;
                    syncActivity?.IsVisible = false;
                    syncStatusLabel?.Text = "";
                });
            }
            catch (Exception ex)
            {
                logService.LogAction($"Sync failed: {ex.Message}");

                // Display error UI
                Microsoft.Maui.Controls.Application.Current.Dispatcher.Dispatch(() =>
                {
                    syncActivity?.IsRunning = false;
                    syncActivity?.IsVisible = false;
                    syncStatusLabel?.Text = "Sync failed";
                });
            }
        }

        // --- Credential helpers ---

        private static async Task EnsureDefaultCredentialsAsync()
        {
            try
            {
                var existing = await SecureStorage.GetAsync(KeyUsername);
                if (string.IsNullOrEmpty(existing))
                {
                    await CreateStoredCredentialsAsync("admin", "password123");
                }
            }
            catch (Exception)
            {
                // Swallowing the exception here.
            }
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
                if (string.IsNullOrEmpty(storedUser) || !storedUser.Equals(username, StringComparison.OrdinalIgnoreCase))
                    return false;

                var storedHashB64 = await SecureStorage.GetAsync(KeyPasswordHash);
                var storedSaltB64 = await SecureStorage.GetAsync(KeySalt);
                if (string.IsNullOrEmpty(storedHashB64) || string.IsNullOrEmpty(storedSaltB64))
                    return false;

                var salt = Convert.FromBase64String(storedSaltB64);
                var expectedHash = Convert.FromBase64String(storedHashB64);
                var computedHash = HashPassword(password, salt);

                return CryptographicOperations.FixedTimeEquals(computedHash, expectedHash);
            }
            catch (Exception)
            {
                return false;
            }
        }

        private static byte[] HashPassword(string password, byte[] salt)
        {
            var result = new byte[32];
            Rfc2898DeriveBytes.Pbkdf2(
                password: System.Text.Encoding.UTF8.GetBytes(password),
                salt: salt,
                iterations: 100_000,
                destination: result,
                hashAlgorithm: HashAlgorithmName.SHA256);

            return result;
        }
    }
}
    #endregion