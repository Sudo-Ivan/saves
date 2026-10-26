// SPDX-License-Identifier: 0BSD

using Saves.Sdk;
using Xunit;

public sealed class IntegrationTests
{
    private static bool Live => Environment.GetEnvironmentVariable("SAVES_URL") != null;

    [Fact]
    public async Task Roundtrip()
    {
        if (!Live) return; // skipped without SAVES_URL
        var c = new SavesClient(new Uri(Environment.GetEnvironmentVariable("SAVES_URL")!),
            Environment.GetEnvironmentVariable("SAVES_TOKEN")!);
        var me = await c.MeAsync();
        Assert.NotNull(me);
        var dir = Path.Combine(Path.GetTempPath(), $"sdk-{Environment.ProcessId}");
        Directory.CreateDirectory(Path.Combine(dir, "empty"));
        await File.WriteAllTextAsync(Path.Combine(dir, "hello.txt"), "hi");
        var big = new byte[3 << 20];
        Array.Fill(big, (byte)7);
        await File.WriteAllBytesAsync(Path.Combine(dir, "big.bin"), big);
        var head = await c.PushAsync("sdk-cs", "saves", dir, new PushOptions { Device = "test" });
        Assert.NotEmpty(head);
        var outDir = Path.Combine(Path.GetTempPath(), $"sdk-cs-out-{Environment.ProcessId}");
        await c.PullAsync("sdk-cs", "saves", head, outDir, new PullOptions());
        Assert.Equal("hi", await File.ReadAllTextAsync(Path.Combine(outDir, "save", "hello.txt")));
        Assert.Equal(big, await File.ReadAllBytesAsync(Path.Combine(outDir, "save", "big.bin")));
        Assert.True(Directory.Exists(Path.Combine(outDir, "save", "empty")));
        var t = await c.CreateTokenAsync("sdk-cs", ["read"]);
        await c.PatchTokenAsync(t.RootElement.GetProperty("id").GetString()!, new { name = "sdk2" });
        await c.RevokeTokenAsync(t.RootElement.GetProperty("id").GetString()!);
        Directory.Delete(dir, true);
        Directory.Delete(outDir, true);
    }
}
