using System.Net.Security;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace CoreServer;

// Certificate from Let's Encrypt PEM files. The full chain is prepared once (not per handshake).
// After a renewal run `kill -HUP <pid>` (e.g. from a certbot deploy hook)
// to load the new certificate without dropping connections.
static class Tls
{
    static volatile SslServerAuthenticationOptions? options;
    static PosixSignalRegistration? sighup;

    public static SslServerAuthenticationOptions Options => options!;

    public static void Load()
    {
        var leaf = X509Certificate2.CreateFromPemFile(Config.TlsCertPath, Config.TlsKeyPath);
        if (OperatingSystem.IsWindows())
        {
            // SChannel can't use an ephemeral PEM key, re-import it (only matters for local testing)
            leaf = X509CertificateLoader.LoadPkcs12(leaf.Export(X509ContentType.Pkcs12), null);
        }
        var chain = new X509Certificate2Collection();
        chain.ImportFromPemFile(Config.TlsCertPath);
        if (chain.Count > 0) chain.RemoveAt(0); // the leaf itself

        options = new SslServerAuthenticationOptions
        {
            ServerCertificateContext = SslStreamCertificateContext.Create(leaf, chain, offline: true),
            ApplicationProtocols = [SslApplicationProtocol.Http11],
        };
    }

    public static void ReloadOnSighup()
    {
        sighup = PosixSignalRegistration.Create(PosixSignal.SIGHUP, ctx =>
        {
            ctx.Cancel = true; // don't terminate
            try
            {
                Load();
                Log.Info("TLS certificate reloaded");
            }
            catch (Exception e)
            {
                Log.Error($"TLS certificate reload failed, keeping the old one: {e.Message}");
            }
        });
    }
}
