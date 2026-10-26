// SPDX-License-Identifier: 0BSD

using System.Net;
using System.Text;
using Saves.Sdk;
using Xunit;

public sealed class UnitTests
{
    private sealed class Fake : HttpMessageHandler
    {
        public Func<HttpRequestMessage, HttpResponseMessage> F = _ => new HttpResponseMessage(HttpStatusCode.OK);
        public int Calls;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Calls++;
            return Task.FromResult(F(request));
        }
    }

    private static SavesClient C(HttpMessageHandler h) =>
        new(new Uri("http://x"), "sv1_x", new SavesClientOptions { Handler = h, Retries = 2 });

    [Fact]
    public async Task ProblemParsing()
    {
        var f = new Fake();
        f.F = _ => new HttpResponseMessage((HttpStatusCode)404)
        {
            Content = new StringContent("{\"type\":\"about:blank\",\"title\":\"nf\",\"status\":404,\"code\":\"not_found\",\"detail\":\"d\"}", Encoding.UTF8, "application/problem+json"),
            Headers = { { "X-Request-Id", "r1" } }
        };
        var e = await Assert.ThrowsAsync<SavesException>(() => C(f).MeAsync());
        Assert.Equal(404, e.Status);
        Assert.Equal("not_found", e.Code);
        Assert.Equal("r1", e.RequestId);
    }

    [Fact]
    public async Task Retry429()
    {
        var f = new Fake();
        var n = 0;
        f.F = _ =>
        {
            n++;
            return n < 3
                ? new HttpResponseMessage((HttpStatusCode)429) { Content = new StringContent("{}") }
                : new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{}", Encoding.UTF8, "application/json") };
        };
        await C(f).MeAsync();
        Assert.Equal(3, n);
    }

    [Fact]
    public async Task NoRetryPostOn5xx()
    {
        var f = new Fake();
        f.F = _ => new HttpResponseMessage(HttpStatusCode.InternalServerError) { Content = new StringContent("{}") };
        await Assert.ThrowsAsync<SavesException>(() =>
            C(f).CreateTokenAsync("n", ["read"]));
        Assert.Equal(1, f.Calls);
    }

    [Fact]
    public void TraversalRefused()
    {
        var m = typeof(SavesClient).GetMethod("SafePath", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!;
        var ex = Assert.Throws<System.Reflection.TargetInvocationException>(() => m.Invoke(null, ["../x"]));
        Assert.IsType<SavesException>(ex.InnerException);
    }

    [Fact]
    public void RedactedToString()
    {
        var c = new SavesClient(new Uri("http://x"), "sv1_secret");
        Assert.DoesNotContain("sv1_secret", c.ToString());
    }
}
