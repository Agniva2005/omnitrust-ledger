import { ClipboardCheck, FlaskConical } from "lucide-react";
import Link from "next/link";
import { redirect } from "next/navigation";
import { LabConsole } from "@/app/(app)/security-lab/lab-console";
import { PageHeader } from "@/components/page-header";
import { Button } from "@/components/ui/button";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { can } from "@/lib/auth/rbac";
import { getSession } from "@/lib/auth/session";
import { listDocuments } from "@/lib/documents/service";
import { SCENARIOS } from "@/lib/security-lab/catalog";

export const dynamic = "force-dynamic";

export default async function SecurityLabPage() {
  const actor = await getSession();
  if (!actor) redirect("/login");

  const all = can(actor.role, "lab:run") ? await listDocuments(actor) : [];
  // Several documents can share a filename, which in a picker is an easy thing to choose wrongly;
  // only those get a short identifier appended.
  const documents = all.map((document) => {
    const ambiguous = all.filter((candidate) => candidate.filename === document.filename).length > 1;
    return {
      id: document.id,
      filename: ambiguous ? `${document.filename} · ${document.id.slice(-6)}` : document.filename,
    };
  });

  return (
    <div className="space-y-6">
      <PageHeader
        icon={FlaskConical}
        eyebrow="Evaluation"
        title="Security Lab"
        actions={
          can(actor.role, "lab:run") ? (
            <Button asChild>
              <Link href="/security-lab/evaluation">
                <ClipboardCheck aria-hidden /> Evaluation
              </Link>
            </Button>
          ) : null
        }
        description="Real attacks against real controls. Each run happens in a separate process with its own freshly created database, document storage and master key, which are deleted afterwards. A scenario can write nothing back, and reaches none of this application's database, storage or keys; the one thing that may cross is a plaintext copy of a document you choose as the subject, so an attack can be shown against your own file. Every run records its before-and-after record counts as evidence. A scenario reports whether the control held; nothing here is simulated."
      />

      {!can(actor.role, "lab:run") && (
        <Card>
          <CardHeader>
            <CardTitle>Admins only</CardTitle>
            <CardDescription>
              Role {actor.role} cannot run Security Lab scenarios. Sign in as admin@demo. The catalogue below shows what each scenario attacks and which control
              it tests.
            </CardDescription>
          </CardHeader>
        </Card>
      )}
      <LabConsole scenarios={SCENARIOS} canRun={can(actor.role, "lab:run")} documents={documents} />
    </div>
  );
}
