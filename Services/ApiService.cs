using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Json;
using System.Threading.Tasks;
using System.Threading;
using AssetGuard.Models;
using System.IO;
using System.Text.Json;
using Microsoft.Maui.Storage;

namespace AssetGuard.Services
{
    // Simple API client used only for demonstration/sync in this sample.
    public class ApiService
    {
        private readonly HttpClient http;
        private readonly string baseUrl;
        private readonly bool useMockServer;
        private readonly string mockFilePath;

        public ApiService(string baseUrl)
        {
            this.baseUrl = baseUrl?.TrimEnd('/') ?? string.Empty;
            http = new HttpClient { BaseAddress = new Uri(this.baseUrl) };
            // If no real API configured (placeholder), use a local file to emulate server
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
                    return new List<Item>();
                var txt = await File.ReadAllTextAsync(mockFilePath, ct);
                try
                {
                    var items = JsonSerializer.Deserialize<List<Item>>(txt);
                    return items ?? new List<Item>();
                }
                catch
                {
                    return new List<Item>();
                }
            }
            return await WithRetriesAsync(async () =>
            {
                // Use a relative URI (no leading slash) so BaseAddress path segment is preserved
                using var res = await http.GetAsync("items", ct);
                if (!res.IsSuccessStatusCode)
                {
                    var body = await res.Content.ReadAsStringAsync(ct);
                    throw new HttpRequestException($"GET items failed: {(int)res.StatusCode} {res.ReasonPhrase} - {body}");
                }
                var items = await res.Content.ReadFromJsonAsync<List<Item>>(cancellationToken: ct);
                return items ?? new List<Item>();
            });
        }

        public async Task<bool> PushItemsAsync(IEnumerable<Item> items, CancellationToken ct = default)
        {
            if (useMockServer)
            {
                // emulate network latency
                await Task.Delay(150, ct);
                try
                {
                    var list = new List<Item>(items);
                    var txt = JsonSerializer.Serialize(list, new JsonSerializerOptions { WriteIndented = true });
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
