import type { NextConfig } from "next";
import { securityHeaders } from "./lib/http/security-headers";

const nextConfig: NextConfig = {
  serverExternalPackages: ["@prisma/client", "bcryptjs"],
  poweredByHeader: false,
  // The development-only route indicator sat on top of the sidebar's demo notice.
  devIndicators: false,
  async headers() {
    return [
      {
        source: "/:path*",
        headers: securityHeaders(process.env.NODE_ENV !== "production"),
      },
    ];
  },
};

export default nextConfig;
