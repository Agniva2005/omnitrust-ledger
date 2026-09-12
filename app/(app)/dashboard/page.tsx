import { redirect } from "next/navigation";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { capabilitiesFor } from "@/lib/auth/rbac";
import { getSession } from "@/lib/auth/session";

export default async function DashboardPage() {
  const actor = await getSession();
  if (!actor) redirect("/login");

  const capabilities = capabilitiesFor(actor.role);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Dashboard</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Signed in as {actor.email} with role {actor.role}.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Your permissions</CardTitle>
          <CardDescription>
            Resolved from the role-to-capability map in lib/auth/rbac.ts. Every API route and
            server action checks against this same map.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          {capabilities.map((capability) => (
            <Badge key={capability} variant="secondary">
              {capability}
            </Badge>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}
