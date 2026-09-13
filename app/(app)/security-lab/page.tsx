import { redirect } from "next/navigation";
import { LabConsole } from "@/app/(app)/security-lab/lab-console";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { can } from "@/lib/auth/rbac";
import { getSession } from "@/lib/auth/session";
import { SCENARIOS } from "@/lib/security-lab/catalog";

export const dynamic = "force-dynamic";

export default async function SecurityLabPage() {
  const actor = await getSession();
  if (!actor) redirect("/login");

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Security Lab</h1>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
          Real attacks against real controls. Each run happens in a separate process with its own
          freshly created database, document storage and master key, which are deleted afterwards.
          The application&apos;s own data is never reachable from a scenario, and every run records its
          before-and-after record counts as evidence. A scenario reports whether the control held;
          nothing here is simulated.
        </p>
      </div>

      {can(actor.role, "lab:run") ? (
        <LabConsole scenarios={SCENARIOS} />
      ) : (
        <Card>
          <CardHeader>
            <CardTitle>Admins only</CardTitle>
            <CardDescription>Role {actor.role} cannot run Security Lab scenarios. Sign in as admin@demo.</CardDescription>
          </CardHeader>
        </Card>
      )}
    </div>
  );
}
