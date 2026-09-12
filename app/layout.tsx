import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "OmniTrust Ledger",
  description:
    "PKI-driven document management with algorithm-agnostic multi-algorithm signature orchestration (demo build).",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen antialiased">
        <div className="flex min-h-screen flex-col">
          <main className="flex-1">{children}</main>
          <footer className="border-t bg-muted/40 px-6 py-4 text-xs text-muted-foreground">
            <span className="font-medium text-destructive">Demo / Not for Production Use.</span>{" "}
            The Certificate Authority here is self-signed and trusted by nothing outside this app;
            private keys are encrypted with a key stored in a local file rather than an HSM or KMS.
          </footer>
        </div>
      </body>
    </html>
  );
}
