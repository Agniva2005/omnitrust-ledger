import { redirect } from "next/navigation";
import { LoginForm } from "@/app/login/login-form";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { getSession } from "@/lib/auth/session";

export default async function LoginPage() {
  if (await getSession()) redirect("/dashboard");

  return (
    <div className="mx-auto flex max-w-md flex-col justify-center px-6 py-20">
      <Card>
        <CardHeader>
          <CardTitle>Sign in to OmniTrust Ledger</CardTitle>
          <CardDescription>
            Demo accounts are listed in the README; all three share the password{" "}
            <code className="rounded bg-muted px-1 py-0.5 text-xs">demo1234</code>.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <LoginForm />
        </CardContent>
      </Card>
    </div>
  );
}
