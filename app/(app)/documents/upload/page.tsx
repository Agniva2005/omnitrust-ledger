import { FileCheck2, Hash, Lock, Upload } from "lucide-react";
import { redirect } from "next/navigation";
import { UploadForm } from "@/app/(app)/documents/upload/upload-form";
import { PageHeader } from "@/components/page-header";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { can } from "@/lib/auth/rbac";
import { getSession } from "@/lib/auth/session";

export const metadata = { title: "Upload document" };

const STEPS = [
  { icon: Hash, title: "Hashed", detail: "SHA-256 of the exact bytes, computed on the server and shown on the document page." },
  { icon: Lock, title: "Encrypted at rest", detail: "Stored with AES-256-GCM under storage/documents; tampering with the blob is detected on read." },
  { icon: FileCheck2, title: "Not signed yet", detail: "Signing is a separate, explicit step with a certificate you choose." },
];

export default async function UploadPage() {
  const actor = await getSession();
  if (!actor) redirect("/login");

  if (!can(actor.role, "document:upload")) {
    return (
      <div className="space-y-6">
        <PageHeader icon={Upload} title="Upload a document" />
        <div className="rounded-xl border border-destructive/40 bg-destructive/5 p-6">
          <h2 className="font-semibold">Not permitted</h2>
          <p className="mt-1 text-sm text-muted-foreground">
            Role {actor.role} cannot upload documents. Sign in as admin@demo or signer@demo.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader icon={Upload} eyebrow="Records" title="Upload a document" description="The file is hashed with SHA-256 and stored encrypted. Nothing is signed yet — signing is a separate, explicit step." />
      <div className="grid gap-6 lg:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
        <Card>
          <CardHeader>
            <CardTitle>Choose a file</CardTitle>
            <CardDescription>You will be taken to the document page, where you can sign it.</CardDescription>
          </CardHeader>
          <CardContent>
            <UploadForm />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>What happens on upload</CardTitle>
          </CardHeader>
          <CardContent>
            <ol className="space-y-4">
              {STEPS.map(({ icon: Icon, title, detail }, index) => (
                <li key={title} className="flex gap-3">
                  <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg border bg-muted/40 text-primary">
                    <Icon aria-hidden className="h-4 w-4" />
                  </span>
                  <div>
                    <div className="text-sm font-medium">
                      {index + 1}. {title}
                    </div>
                    <p className="mt-0.5 text-xs leading-relaxed text-muted-foreground">{detail}</p>
                  </div>
                </li>
              ))}
            </ol>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
