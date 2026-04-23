using System.Net.Http.Json;
using AssetGuard.Models;
using System.Text.Json;

namespace AssetGuard.Services
{
    // Initialize the JsonSerializerOptions once and reuse it for all serialization/deserialization operations.
    public class ApiService
    {
        private readonly HttpClient http;
        private readonly string baseUrl;
        private readonly bool useMockServer;
        private readonly string mockFilePath;

        // Use a static or readonly instance for JsonSerializerOptions to avoid recreation.
        private static readonly JsonSerializerOptions SerializerOptions = new JsonSerializerOptions { WriteIndented = true };

        public ApiService(string baseUrl)
        {
            this.baseUrl = baseUrl?.TrimEnd('/') ?? string.Empty;
            http = new HttpClient { BaseAddress = new Uri(this.baseUrl) };

            // use a local file to emulate server
            useMockServer = string.IsNullOrWhiteSpace(this.baseUrl) || this.baseUrl.Contains("example.com", StringComparison.OrdinalIgnoreCase);
            mockFilePath = Path.Combine(FileSystem.AppDataDirectory, "mock_server_items.json");
        }

        // Retries with exponential backoff for transient network issues
        private static async Task<T?> WithRetriesAsync<T>(Func<Task<T>> operation, int maxAttempts = 3, int initialDelayMs = 300)
        {
            var attempts = 0;
            var delay = initialDelayMs;
            while (true)
            {
                try
                {
                    return await operation();
                }
                catch (Exception)
                {
                    attempts++;
                    if (attempts >= maxAttempts)
                        throw;
                    await Task.Delay(delay);
                    delay *= 2;
                }
            }
        }

        public async Task<IList<Item>> GetItemsAsync(CancellationToken ct = default)
        {
            if (useMockServer)
            {
                // emulate network latency
                await Task.Delay(150, ct);
                if (!File.Exists(mockFilePath))
                    return [];

                var txt = await File.ReadAllTextAsync(mockFilePath, ct);

                try
                {
                    // Simplified null handling and reused SerializerOptions
                    if (string.IsNullOrWhiteSpace(txt))
                        return [];

                    var items = JsonSerializer.Deserialize<List<Item>>(txt, SerializerOptions);
                    // Ensure we never return null
                    return items ?? [];
                }
                catch
                {
                    return [];
                }
            }
            List<Item>? items1 = await WithRetriesAsync(async () =>
            {
               
                using var res = await http.GetAsync("items", ct);
                if (!res.IsSuccessStatusCode)
                {
                    var body = await res.Content.ReadAsStringAsync(ct);
                    throw new HttpRequestException($"GET items failed: {(int)res.StatusCode} {res.ReasonPhrase} - {body}");
                }

                
                var items = await res.Content.ReadFromJsonAsync<List<Item>>(cancellationToken: ct);
                
                return items ?? [];
            });
            return items1;
        }

        public async Task<bool> PushItemsAsync(IEnumerable<Item> items, CancellationToken ct = default)
        {
            if (useMockServer)
            {
                // emulate network latency
                await Task.Delay(150, ct);
                try
                {
                    // Use the reusable SerializerOptions
                    var list = new List<Item>(items);
                    var txt = JsonSerializer.Serialize(list, SerializerOptions);
                    await File.WriteAllTextAsync(mockFilePath, txt, ct);
                    return true;
                }
                catch (Exception ex)
                {
                    throw new HttpRequestException($"Mock push failed: {ex.Message}", ex);
                }
            }
            return await WithRetriesAsync(async () =>
            {
                // Use a relative URI so BaseAddress path is preserved (avoid leading slash)
                using var res = await http.PostAsJsonAsync("items/sync", items, ct);
                if (!res.IsSuccessStatusCode)
                {
                    var body = await res.Content.ReadAsStringAsync(ct);
                    throw new HttpRequestException($"POST items/sync failed: {(int)res.StatusCode} {res.ReasonPhrase} - {body}");
                }
                return true;
            });
        }
    }
}
