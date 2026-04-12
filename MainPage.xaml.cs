using AssetGuard.Models;
using AssetGuard.Services;
using Microsoft.Maui.Controls;
using Microsoft.Maui.Storage;
using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace AssetGuard
{
    public partial class MainPage : ContentPage
    {
        private readonly ItemRepository itemRepository;
        private readonly LogService logService;
        private static readonly string DbPath = Path.Combine(FileSystem.AppDataDirectory, "items.db");

        public ObservableCollection<string> Items { get; } = [];

        private string selectedItem = string.Empty;
        public string SelectedItem
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

            foreach (var item in itemRepository.LoadItems())
                Items.Add(item);

            // Ensure credentials exist (create default if absent). Fire-and-forget is OK here; handle exceptions inside.
            _ = MainPage.EnsureDefaultCredentialsAsync();
        }
        #endregion

        #region:Methods of MainPage
        private async void OnAddButtonClicked(object? sender, EventArgs e)
        {
            try
            {
                if (!string.IsNullOrWhiteSpace(ItemEditor?.Text))
                {
                    itemRepository.AddItem(ItemEditor.Text);
                    Items.Clear();
                    foreach (var item in itemRepository.LoadItems())
                        Items.Add(item);
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
                if (!string.IsNullOrEmpty(SelectedItem))
                {
                    itemRepository.RemoveItem(SelectedItem);
                    Items.Clear();
                    foreach (var item in itemRepository.LoadItems())
                        Items.Add(item);
                    logService.LogAction($"User removed item: '{SelectedItem}'");
                    SelectedItem = string.Empty;
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
                if (!string.IsNullOrEmpty(SelectedItem) && !string.IsNullOrWhiteSpace(ItemEditor?.Text))
                {
                    itemRepository.EditItem(SelectedItem, ItemEditor.Text);
                    Items.Clear();
                    foreach (var item in itemRepository.LoadItems())
                        Items.Add(item);
                    logService.LogAction($"User edited item: '{ItemEditor.Text}'");
                    SelectedItem = string.Empty;
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
                    logService.LogAction($"User '{username}' logged in.");
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
            if (loginGrid != null && mainGrid != null)
            {
                loginGrid.IsVisible = true;
                mainGrid.IsVisible = false;
            }

            usernameEntry?.Text = string.Empty;
            passwordEntry?.Text = string.Empty;
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

        // --- Credential helpers ---

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
    }
}
    #endregion