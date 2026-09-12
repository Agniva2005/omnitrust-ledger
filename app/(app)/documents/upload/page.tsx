import { redirect } from "next/navigation";
import { UploadForm } from "@/app/(app)/documents/upload/upload-form";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { can } from "@/lib/auth/rbac";
import { getSession } from "@/lib/auth/session";

export default async function UploadPage() {
  const actor = await getSession();
  if (!actor) redirect("/login");

  if (!can(actor.role, "document:upload")) {
    return (
      <div className="rounded-lg border border-destructive/40 bg-destructive/5 p-6">
        <h1 className="font-semibold">Not permitted</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Role {actor.role} cannot upload documents. Sign in as admin@demo or signer@demo.
        </p>
      </div>
    );
  }

  return (
    <div className="max-w-xl">
      <Card>
        <CardHeader>
          <CardTitle>Upload a document</CardTitle>
          <CardDescription>
            The file is hashed with SHA-256 and stored encrypted (AES-256-GCM) under
            storage/documents. Nothing is signed yet &mdash; signing is a separate, explicit step.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <UploadForm />
        </CardContent>
      </Card>
    </div>
  );
}
