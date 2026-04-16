using AssetGuard.Models;
using AssetGuard.Services;
using Microsoft.Maui.Controls;
using Microsoft.Maui.Storage;
using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

#nullable disable

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

        private Item? selectedItem = null;
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

            usernameEntry = this.FindByName<Entry>("UsernameEntry");
            passwordEntry = this.FindByName<Entry>("PasswordEntry");
            mainGrid = this.FindByName<Grid>("MainGrid");
            loginGrid = this.FindByName<Grid>("LoginGrid");

            var tableName = "Items";
            var logFilePath = Path.Combine(FileSystem.AppDataDirectory, "useractions.log");

            itemRepository = new ItemRepository(DbPath, tableName);
            logService = new LogService(logFilePath);

            // API client used when in "online" mode
            apiService = new ApiService(ApiBaseUrl);

            // Defer loading and state initialization to async initializer
            _ = InitializeAsync();

            // Ensure credentials exist (create default if absent). Fire-and-forget is OK here; handle exceptions inside.
            _ = MainPage.EnsureDefaultCredentialsAsync();
        }
        #endregion

        private void RefreshLocalItems()
        {
            var local = itemRepository.LoadItems();
            Microsoft.Maui.ApplicationModel.MainThread.BeginInvokeOnMainThread(() =>
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
                Microsoft.Maui.ApplicationModel.MainThread.BeginInvokeOnMainThread(() =>
                {
                    var onlineSwitch = this.FindByName<Switch>("OnlineSwitch");
                    var onlineLabel = this.FindByName<Label>("OnlineStatusLabel");
                    if (onlineSwitch != null) onlineSwitch.IsToggled = isOnline;
                    if (onlineLabel != null) onlineLabel.Text = isOnline ? "Online" : "Offline";
                });

                if (isOnline)
                {
                    // If online, run full sync which will update UI with correct sync states
                    await SyncWithServerAsync();
                }
                else
                {
                    // Offline: show local items and mark them accordingly
                    Microsoft.Maui.ApplicationModel.MainThread.BeginInvokeOnMainThread(() =>
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
            catch
            {
                // If initialization fails, fall back to showing local DB items as local
                var list = itemRepository.LoadItems();
                Microsoft.Maui.ApplicationModel.MainThread.BeginInvokeOnMainThread(() =>
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
                if (!string.IsNullOrWhiteSpace(ItemEditor?.Text))
                {
                    itemRepository.AddItem(ItemEditor.Text);
                    // pull updated items and add new item to UI
                    var list = itemRepository.LoadItems();
                    Items.Clear();
                    foreach (var it in list)
                    {
                        it.SyncState = 1;
                        Items.Add(it);
                    }
                    logService.LogAction($"User added item: '{ItemEditor.Text}'");
                    ItemEditor.Text = string.Empty;
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
                var newText = ItemEditor?.Text;
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
                    ItemEditor.Text = string.Empty;
                }
            }
            catch (Exception ex)
            {
                await DisplayAlertAsync("Error", $"Edit failed: {ex.Message}", "OK");
            }
        }
        #endregion

        #region:Login/Logout and credential handling

        // Make login async and verify against securely stored hash+salt in SecureStorage
        private async void OnLoginClicked(object? sender, EventArgs e)
        {
            try
            {
                var username = usernameEntry?.Text ?? string.Empty;
                var password = passwordEntry?.Text ?? string.Empty;

                var verified = await VerifyCredentialsAsync(username, password);
                if (verified)
                {
                    if (loginGrid != null && mainGrid != null)
                    {
                        loginGrid.IsVisible = false;
                        mainGrid.IsVisible = true;
                    }
                    // Track authentication state so sync attempts are gated
                    isAuthenticated = true;
                    logService.LogAction($"User '{username}' logged in.");

                    // Enable online switch now that user is authenticated
                    Microsoft.Maui.ApplicationModel.MainThread.BeginInvokeOnMainThread(() =>
                    {
                        var onlineSwitch = this.FindByName<Switch>("OnlineSwitch");
                        if (onlineSwitch != null) onlineSwitch.IsEnabled = true;
                    });

                    // Refresh UI with local items immediately after login
                    RefreshLocalItems();

                    // If the online switch is currently on, attempt a background sync.
                    // Prefer the UI switch state (reflects current user choice) and fall back to persisted preference.
                    try
                    {
                        var onlineSwitch = this.FindByName<Switch>("OnlineSwitch");
                        if (onlineSwitch != null && onlineSwitch.IsToggled)
                        {
                            _ = SyncWithServerAsync();
                        }
                        else
                        {
                            var val = await SecureStorage.GetAsync(KeyIsOnline);
                            if (val == "1")
                                _ = SyncWithServerAsync();
                        }
                    }
                    catch
                    {
                        // ignore
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
            // toggle visibility using null-conditional access to simplify null checks
            if (loginGrid is not null)
                loginGrid.IsVisible = true;
            if (mainGrid is not null)
                mainGrid.IsVisible = false;

            if (usernameEntry is not null)
                usernameEntry.Text = string.Empty;
            if (passwordEntry is not null)
                passwordEntry.Text = string.Empty;

            // Clear authentication state
            isAuthenticated = false;

            // Leave the online toggle enabled on the login screen so the user can choose the preferred state
            Microsoft.Maui.ApplicationModel.MainThread.BeginInvokeOnMainThread(() =>
            {
                var onlineSwitch = this.FindByName<Switch>("OnlineSwitch");
                var onlineLabel = this.FindByName<Label>("OnlineStatusLabel");
                if (onlineSwitch != null)
                {
                    // show as offline by default but keep control enabled for the user to toggle before login
                    onlineSwitch.IsToggled = false;
                    onlineSwitch.IsEnabled = true;
                }
                if (onlineLabel != null)
                    onlineLabel.Text = "Offline";
            });

            // Persist offline preference but allow the user to change it on the login screen
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

        // Debug helper: open the mock server JSON file used by ApiService when no real API is configured
        private async void OnOpenMockServerClicked(object? sender, EventArgs e)
        {
            var mockPath = Path.Combine(FileSystem.AppDataDirectory, "mock_server_items.json");
            if (File.Exists(mockPath))
            {
                await Launcher.Default.OpenAsync(new OpenFileRequest { File = new ReadOnlyFile(mockPath) });
            }
            else
            {
                await DisplayAlert("Mock Server", "Mock server file not found.", "OK");
            }
        }

        // Debug helper: copy the runtime useractions.log into the repo workspace for easy inspection
        private async void OnCopyLogToRepoClicked(object? sender, EventArgs e)
        {
            try
            {
                var runtimePath = logService.LogFilePath;
                if (!File.Exists(runtimePath))
                {
                    await DisplayAlert("Copy Log", "Runtime log not found.", "OK");
                    return;
                }

                // Try to copy into the local repo workspace (developer machine). Update this path if your workspace is elsewhere.
                var repoRoot = @"C:\Users\willi\source\repos\Mrjelly84\C-P-P";
                string target;
                if (Directory.Exists(repoRoot))
                {
                    target = Path.Combine(repoRoot, "useractions_runtime_copy.log");
                }
                else
                {
                    // Fallback to app's base directory
                    target = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "useractions_runtime_copy.log");
                }

                File.Copy(runtimePath, target, true);
                await DisplayAlert("Copy Log", $"Copied runtime log to: {target}", "OK");
            }
            catch (Exception ex)
            {
                await DisplayAlert("Copy Log", $"Copy failed: {ex.Message}", "OK");
            }
        }

        private void OnOnlineToggled(object sender, ToggledEventArgs e)
        {
            var sw = sender as Switch;
            var label = this.FindByName<Label>("OnlineStatusLabel");
            if (label != null)
                label.Text = e.Value ? "Online" : "Offline";

            // Persist preference in SecureStorage
            _ = SecureStorage.SetAsync(KeyIsOnline, e.Value ? "1" : "0");

            // Update internal online flag
            isOnline = e.Value;

            // If toggled online, sync local db with server (pull then push local)
            // Immediately ensure the UI reflects local storage so user sees their offline items
            var localNow = itemRepository.LoadItems();
            Microsoft.Maui.ApplicationModel.MainThread.BeginInvokeOnMainThread(() =>
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
            try
            {
                // proceed with sync (ApiService supports a mock server mode when no real API is configured)
                // Load local items
                var localItems = itemRepository.LoadItems();

                // Start progress UI
                Microsoft.Maui.ApplicationModel.MainThread.BeginInvokeOnMainThread(() =>
                {
                    var ai = this.FindByName<ActivityIndicator>("SyncActivity");
                    var lbl = this.FindByName<Label>("SyncStatusLabel");
                    if (ai != null) { ai.IsVisible = true; ai.IsRunning = true; }
                    if (lbl != null) lbl.Text = "Syncing...";
                });

                // Push local items to server (send local changes first)
                if (!isAuthenticated)
                {
                    logService.LogAction("Sync skipped: user not authenticated.");
                    // show offline UI state
                    Microsoft.Maui.ApplicationModel.MainThread.BeginInvokeOnMainThread(() =>
                    {
                        Items.Clear();
                        foreach (var it in localItems)
                        {
                            it.SyncState = 1; // local only
                            Items.Add(it);
                        }
                        var lbl = this.FindByName<Label>("SyncStatusLabel");
                        if (lbl != null) lbl.Text = "Offline";
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
                    latestSyncError = ex.ToString();
                    logService.LogAction($"Sync push failed: {ex}");
                    // Ensure UI shows local state and surface alert
                    Microsoft.Maui.ApplicationModel.MainThread.BeginInvokeOnMainThread(async () =>
                    {
                        Items.Clear();
                        foreach (var it in localItems)
                        {
                            it.SyncState = 1; // local only
                            Items.Add(it);
                        }
                        var lbl = this.FindByName<Label>("SyncStatusLabel");
                        if (lbl != null) lbl.Text = "Offline";
                        var onlineLabel = this.FindByName<Label>("OnlineStatusLabel");
                        if (onlineLabel != null) onlineLabel.Text = "Offline";
                        await DisplayAlert("Sync Error", latestSyncError, "OK");
                    });
                    return;
                }
                if (!pushSucceeded)
                {
                    latestSyncError = "Sync push failed: server returned non-success status.";
                    logService.LogAction(latestSyncError);
                    Microsoft.Maui.ApplicationModel.MainThread.BeginInvokeOnMainThread(async () =>
                    {
                        Items.Clear();
                        foreach (var it in localItems)
                        {
                            it.SyncState = 1;
                            Items.Add(it);
                        }
                        var lbl = this.FindByName<Label>("SyncStatusLabel");
                        if (lbl != null) lbl.Text = "Sync failed";
                        await DisplayAlert("Sync Error", latestSyncError, "OK");
                    });
                    return;
                }

                // Fetch server items
                var serverItems = await apiService.GetItemsAsync();
                if (serverItems == null || !serverItems.Any())
                {
                    // If server returned nothing after a successful push it's unexpected; treat as sync failure
                    latestSyncError = "Sync fetch returned no items: treating as sync failure.";
                    logService.LogAction(latestSyncError);
                    Microsoft.Maui.ApplicationModel.MainThread.BeginInvokeOnMainThread(async () =>
                    {
                        Items.Clear();
                        foreach (var it in localItems)
                        {
                            it.SyncState = 1;
                            Items.Add(it);
                        }
                        var lbl = this.FindByName<Label>("SyncStatusLabel");
                        if (lbl != null) lbl.Text = "Sync failed";
                        await DisplayAlert("Sync Error", latestSyncError, "OK");
                    });
                    return;
                }

                // Resolve per-item conflicts by LastModified (last-write-wins)
                var merged = new Dictionary<string, Item>(StringComparer.OrdinalIgnoreCase);
                foreach (var it in localItems)
                    merged[it.Id] = it;
                foreach (var sit in serverItems)
                {
                    if (!merged.TryGetValue(sit.Id, out var existing) || sit.LastModified > existing.LastModified)
                    {
                        merged[sit.Id] = sit;
                    }
                }

                var mergedList = merged.Values.OrderBy(i => i.LastModified).ToList();

                // Update sync state per item: if present only locally before merge mark Local (1), if newer than server mark Modified (2)
                foreach (var it in mergedList)
                {
                    // default: synced
                    it.SyncState = 0;
                }

                // Detect local-only items
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
                        if (local != null && server != null && local.LastModified > server.LastModified)
                            it.SyncState = 2; // modified locally
                    }
                }

                // Update local DB and UI with merged collection
                itemRepository.ReplaceAll(mergedList);
                Microsoft.Maui.ApplicationModel.MainThread.BeginInvokeOnMainThread(() =>
                {
                    Items.Clear();
                    foreach (var it in mergedList)
                        Items.Add(it);
                });

                // Push merged collection back to server
                await apiService.PushItemsAsync(mergedList);

                logService.LogAction("Sync completed (per-item last-write-wins).");

                // End progress UI
                Microsoft.Maui.ApplicationModel.MainThread.BeginInvokeOnMainThread(() =>
                {
                    var ai = this.FindByName<ActivityIndicator>("SyncActivity");
                    var lbl = this.FindByName<Label>("SyncStatusLabel");
                    if (ai != null) { ai.IsRunning = false; ai.IsVisible = false; }
                    if (lbl != null) lbl.Text = "";
                });
            }
            catch (Exception ex)
            {
                // Sync failures should not crash app; log the error
                logService.LogAction($"Sync failed: {ex.Message}");
                Microsoft.Maui.ApplicationModel.MainThread.BeginInvokeOnMainThread(() =>
                {
                    var ai = this.FindByName<ActivityIndicator>("SyncActivity");
                    var lbl = this.FindByName<Label>("SyncStatusLabel");
                    if (ai != null) { ai.IsRunning = false; ai.IsVisible = false; }
                    if (lbl != null) lbl.Text = "Sync failed";
                });
            }
        }

        // --- Credential helpers ---

        private async Task RestoreOnlineStateAsync()
        {
            try
            {
                var val = await SecureStorage.GetAsync(KeyIsOnline);
                var isOnline = val == "1";

                var onlineSwitch = this.FindByName<Switch>("OnlineSwitch");
                var onlineLabel = this.FindByName<Label>("OnlineStatusLabel");
                if (onlineSwitch != null)
                    onlineSwitch.IsToggled = isOnline;
                if (onlineLabel != null)
                    onlineLabel.Text = isOnline ? "Online" : "Offline";

                if (isOnline)
                    await SyncWithServerAsync();
            }
            catch
            {
                // ignore
            }
        }

        private static async Task EnsureDefaultCredentialsAsync()
        {
            try
            {
                var existing = await SecureStorage.GetAsync(KeyUsername);
                if (string.IsNullOrEmpty(existing))
                {
                    // Create a safe default for first run. Change immediately in production.
                    await CreateStoredCredentialsAsync("admin", "password123");
                }
            }
            catch
            {
                // SecureStorage may throw on some emulators/unsupported platforms.
                // Swallowing the exception keeps app usable; consider notifying or using a fallback storage.
            }
        }

        // Creates and stores username, salted password hash in SecureStorage
        private static async Task CreateStoredCredentialsAsync(string username, string password)
        {
            var salt = RandomNumberGenerator.GetBytes(16);
            var hash = HashPassword(password, salt);

            await SecureStorage.SetAsync(KeyUsername, username);
            await SecureStorage.SetAsync(KeyPasswordHash, Convert.ToBase64String(hash));
            await SecureStorage.SetAsync(KeySalt, Convert.ToBase64String(salt));
        }

        // Verifies credentials by recomputing hash from stored salt and comparing in constant time.
        private static async Task<bool> VerifyCredentialsAsync(string username, string password)
        {
            try
            {
                var storedUser = await SecureStorage.GetAsync(KeyUsername);
                if (string.IsNullOrEmpty(storedUser) || storedUser != username)
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
            catch
            {
                // On error, treat as authentication failure
                return false;
            }
        }

        private static byte[] HashPassword(string password, byte[] salt)
        {
            // PBKDF2 with SHA-256, 100k iterations, 32-byte derived key
            var result = new byte[32];
            Rfc2898DeriveBytes.Pbkdf2(
                password: System.Text.Encoding.UTF8.GetBytes(password),
                salt: salt,
                iterations: 100_000,
                destination: result,
                hashAlgorithm: HashAlgorithmName.SHA256);
            return result;
        }
        #endregion
    }
}
