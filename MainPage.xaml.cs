using AssetGuard.Models;
using AssetGuard.Services;
using AssetGuard.ViewModels;
using System.Collections.ObjectModel;
using System.Security.Cryptography;

namespace AssetGuard
{
    public partial class MainPage : ContentPage
    {
        // ViewModels
        private readonly LoginViewModel _loginViewModel = new();
        private readonly ItemViewModel _itemViewModel;

        // Services
        private readonly ItemRepository _itemRepository;
        private readonly LogService _logService;
        private readonly ApiService _apiService;

        // Settings
        private static readonly string DbPath = Path.Combine(FileSystem.AppDataDirectory, "items.db");
        private const string ApiBaseUrl = "https://example.com/api";
        private const string KeyIsOnline = "pref_is_online";

        public bool isOnline = false;
        public bool isAuthenticated = false;

        public MainPage()
        {
            SQLitePCL.Batteries.Init();
            InitializeComponent();

            // Initialize Services
            var logFilePath = Path.Combine(FileSystem.AppDataDirectory, "useractions.log");
            _itemRepository = new ItemRepository(DbPath, "Items");
            _logService = new LogService(logFilePath);
            _apiService = new ApiService(ApiBaseUrl);

            // Initialize ItemViewModel and link it to the UI
            _itemViewModel = new ItemViewModel(_itemRepository, _logService);
            BindingContext = _itemViewModel;

            _ = InitializeAsync();
            _ = EnsureDefaultCredentialsAsync();
        }

        private async Task InitializeAsync()
        {
            try
            {
                var val = await SecureStorage.GetAsync(KeyIsOnline);
                isOnline = val == "1";

                MainThread.BeginInvokeOnMainThread(() =>
                {
                    OnlineSwitch.IsToggled = isOnline;
                    OnlineStatusLabel.Text = isOnline ? "Online" : "Offline";
                });

                if (isOnline)
                {
                    await SyncWithServerAsync();
                }
                else
                {
                    _itemViewModel.RefreshItems();
                }
            }
            catch (Exception)
            {
                _itemViewModel.RefreshItems();
            }
        }

        #region Item Management (Delegated to ViewModel)

        public void OnAddButtonClicked(object? sender, EventArgs e)
        {
            // Transfer text from Entry to ViewModel then call Add
            _itemViewModel.NewItemText = ItemEditor.Text;
            _itemViewModel.AddItem();
            ItemEditor.Text = string.Empty; // Clear UI
        }

        public void OnRemoveButtonClicked(object? sender, EventArgs e)
        {
            _itemViewModel.RemoveItem();
        }

        public void OnEditButtonClicked(object? sender, EventArgs e)
        {
            // For editing, we update the selected item's detail with current Entry text
            if (_itemViewModel.SelectedItem != null && !string.IsNullOrWhiteSpace(ItemEditor.Text))
            {
                _itemRepository.EditItem(_itemViewModel.SelectedItem.Id, ItemEditor.Text);
                _logService.LogAction($"User edited item: '{ItemEditor.Text}'");
                ItemEditor.Text = string.Empty;
                _itemViewModel.RefreshItems();
            }
        }

        #endregion

        #region Login/Logout Handling

        // XAML Event Handler (Satisfies MAUIX2014)
        public void OnLoginClicked(object sender, EventArgs e)
        {
            _ = OnLoginClickedAsync(sender, e);
        }

        // Async Logic (Satisfies Unit Tests/CS4008)
        public async Task OnLoginClickedAsync(object sender, EventArgs e)
        {
            try
            {
                var username = UsernameEntry.Text ?? string.Empty;
                var password = PasswordEntry.Text ?? string.Empty;

                var verified = await _loginViewModel.VerifyCredentialsAsync(username, password);

                if (verified)
                {
                    LoginGrid.IsVisible = false;
                    MainGrid.IsVisible = true;
                    isAuthenticated = true;

                    _logService.LogAction($"User '{username}' logged in.");
                    _itemViewModel.RefreshItems();

                    if (OnlineSwitch.IsToggled) await SyncWithServerAsync();
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
            LoginGrid.IsVisible = true;
            MainGrid.IsVisible = false;
            UsernameEntry.Text = string.Empty;
            PasswordEntry.Text = string.Empty;

            isAuthenticated = false;
            isOnline = false;
            OnlineSwitch.IsToggled = false;

            _ = SecureStorage.SetAsync(KeyIsOnline, "0");
        }

        #endregion

        #region Sync and Helpers

        public void OnOnlineToggled(object sender, ToggledEventArgs e)
        {
            isOnline = e.Value;
            OnlineStatusLabel.Text = isOnline ? "Online" : "Offline";
            _ = SecureStorage.SetAsync(KeyIsOnline, isOnline ? "1" : "0");

            if (isOnline) _ = SyncWithServerAsync();
        }

        public async Task SyncWithServerAsync()
        {
            if (SyncActivity.IsRunning) return;

            try
            {
                SyncActivity.IsVisible = true;
                SyncActivity.IsRunning = true;
                SyncStatusLabel.Text = "Syncing...";

                var localItems = _itemRepository.LoadItems();
                bool pushSucceeded = await _apiService.PushItemsAsync(localItems);
                var serverItems = await _apiService.GetItemsAsync();

                if (pushSucceeded && serverItems != null)
                {
                    // Basic merge logic
                    _itemRepository.ReplaceAll(serverItems);
                    _itemViewModel.RefreshItems();
                }

                SyncStatusLabel.Text = string.Empty;
            }
            catch (Exception ex)
            {
                SyncStatusLabel.Text = "Sync failed";
                _logService.LogAction($"Sync error: {ex.Message}");
            }
            finally
            {
                SyncActivity.IsRunning = false;
                SyncActivity.IsVisible = false;
            }
        }

        private async void OnLogFileTapped(object? sender, TappedEventArgs e)
        {
            if (File.Exists(_logService.LogFilePath))
                await Launcher.Default.OpenAsync(new OpenFileRequest { File = new ReadOnlyFile(_logService.LogFilePath) });
        }

        private static async Task EnsureDefaultCredentialsAsync()
        {
            var existing = await SecureStorage.GetAsync("cred_username");
            if (string.IsNullOrEmpty(existing))
            {
                var salt = RandomNumberGenerator.GetBytes(16);
                var hash = LoginViewModel.HashPassword("password123", salt);
                await SecureStorage.SetAsync("cred_username", "admin");
                await SecureStorage.SetAsync("cred_password_hash", Convert.ToBase64String(hash));
                await SecureStorage.SetAsync("cred_salt", Convert.ToBase64String(salt));
            }
        }
        #endregion
    }
}