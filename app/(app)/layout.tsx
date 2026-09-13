import { redirect } from "next/navigation";
import { AppShell } from "@/components/app-shell";
import { getSession } from "@/lib/auth/session";

export default async function AppLayout({ children }: { children: React.ReactNode }) {
  const actor = await getSession();
  if (!actor) redirect("/login");

  return <AppShell user={{ email: actor.email, role: actor.role }}>{children}</AppShell>;
}
