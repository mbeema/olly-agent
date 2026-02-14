// .NET pricing-service for cross-language tracing demo.
// ASP.NET Core 8.0 minimal API. Calls Node.js stock-service for stock enrichment.

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseUrls($"http://0.0.0.0:{Environment.GetEnvironmentVariable("PORT") ?? "8082"}");

var app = builder.Build();

var stockServiceUrl = Environment.GetEnvironmentVariable("STOCK_SERVICE_URL") ?? "http://localhost:8083";

// In-memory pricing data (matches inventory SKUs)
var pricing = new Dictionary<string, PricingInfo>
{
    ["WDG-001"] = new("WDG-001", 29.99m, 10, "USD"),
    ["GDG-001"] = new("GDG-001", 49.99m, 5, "USD"),
    ["SPR-001"] = new("SPR-001", 14.99m, 15, "USD"),
    ["GZM-001"] = new("GZM-001", 89.99m, 20, "USD"),
    ["DHK-001"] = new("DHK-001", 34.99m, 0, "USD"),
};

app.MapGet("/api/health", () => Results.Ok(new { status = "ok", service = "pricing-service" }));

app.MapGet("/api/pricing", () => Results.Ok(pricing.Values));

app.MapGet("/api/pricing/{sku}", (string sku) =>
{
    var key = sku.ToUpperInvariant();
    if (!pricing.TryGetValue(key, out var info))
        return Results.NotFound(new { error = "pricing not found", sku = key });

    var finalPrice = info.BasePrice * (1 - info.DiscountPct / 100m);

    // Call stock-service for stock enrichment.
    // Use synchronous HttpWebRequest so connect/write/read stay on the same OS thread.
    // This ensures eBPF FD-based causal tracking correctly links outbound→inbound.
    object? stock = null;
    try
    {
        var req = System.Net.WebRequest.CreateHttp($"{stockServiceUrl}/api/stock/{key}");
        req.Timeout = 5000;
        using var resp = req.GetResponse();
        using var reader = new System.IO.StreamReader(resp.GetResponseStream()!);
        var body = reader.ReadToEnd();
        stock = System.Text.Json.JsonSerializer.Deserialize<object>(body);
    }
    catch (Exception ex)
    {
        stock = new { error = "stock-service unreachable", detail = ex.Message };
    }

    return Results.Ok(new
    {
        sku = key,
        base_price = info.BasePrice,
        discount_pct = info.DiscountPct,
        final_price = Math.Round(finalPrice, 2),
        currency = info.Currency,
        stock
    });
});

app.Run();

record PricingInfo(string Sku, decimal BasePrice, int DiscountPct, string Currency);
