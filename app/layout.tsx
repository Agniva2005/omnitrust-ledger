import type { Metadata, Viewport } from "next";
import { themeBootstrapScript } from "@/lib/ui/theme-script";
import "./globals.css";

export const metadata: Metadata = {
  title: { default: "OmniTrust Ledger", template: "%s · OmniTrust Ledger" },
  description:
    "PKI-driven document management with algorithm-agnostic multi-algorithm signature orchestration (demo build).",
};

export const viewport: Viewport = {
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#f8f9fb" },
    { media: "(prefers-color-scheme: dark)", color: "#0c0e14" },
  ],
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    // The bootstrap script sets the theme class and sidebar state before hydration, so React is told to expect them.
    <html lang="en" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeBootstrapScript }} />
      </head>
      <body className="min-h-screen antialiased">{children}</body>
    </html>
  );
}
