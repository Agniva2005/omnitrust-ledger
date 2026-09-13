"use client";

import * as Dialog from "@radix-ui/react-dialog";
import {
  ChevronRight,
  CornerDownLeft,
  FileText,
  FlaskConical,
  Gauge,
  KeyRound,
  LayoutDashboard,
  Link2,
  LogOut,
  Menu,
  PanelLeftClose,
  PanelLeftOpen,
  ScrollText,
  Search,
  ShieldCheck,
  Upload,
  X,
  type LucideIcon,
} from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { DemoNotice } from "@/components/demo-notice";
import { ThemeToggle, applyTheme, readThemePreference } from "@/components/theme-toggle";
import { SIDEBAR_STORAGE_KEY } from "@/lib/ui/theme-script";
import { cn } from "@/lib/utils";

type NavItem = { href: string; label: string; icon: LucideIcon; description: string };
type NavGroup = { label: string; items: NavItem[] };

const NAVIGATION: NavGroup[] = [
  {
    label: "Overview",
    items: [{ href: "/dashboard", label: "Dashboard", icon: LayoutDashboard, description: "Live counts, trust services and recent activity" }],
  },
  {
    label: "Records",
    items: [
      { href: "/documents", label: "Documents", icon: FileText, description: "Upload, sign, version and verify documents" },
      { href: "/documents/upload", label: "Upload document", icon: Upload, description: "Add a document and compute its SHA-256" },
    ],
  },
  {
    label: "Trust",
    items: [
      { href: "/certificates", label: "Certificates", icon: ShieldCheck, description: "Issue, explore and revoke X.509 certificates" },
      { href: "/algorithms", label: "Algorithms", icon: KeyRound, description: "Classical, post-quantum and hybrid providers" },
    ],
  },
  {
    label: "Integrity",
    items: [
      { href: "/audit", label: "Audit log", icon: ScrollText, description: "Hash-chained log and signed checkpoints" },
      { href: "/anchoring", label: "Anchoring", icon: Link2, description: "Merkle roots on the local chain" },
    ],
  },
  {
    label: "Evaluation",
    items: [
      { href: "/security-lab", label: "Security Lab", icon: FlaskConical, description: "Real attacks in disposable sandboxes" },
      { href: "/benchmarks", label: "Benchmarks", icon: Gauge, description: "Measured timings with their uncertainty" },
    ],
  },
];

const ALL_ITEMS = NAVIGATION.flatMap((group) => group.items);

const SEGMENT_LABELS: Record<string, string> = Object.fromEntries([
  ...ALL_ITEMS.map((item) => [item.href.split("/").filter(Boolean).at(-1)!, item.label]),
  ["upload", "Upload"],
  ["verify", "Verify"],
]);

function isActive(pathname: string, href: string) {
  if (href === "/documents") return pathname === "/documents" || (pathname.startsWith("/documents/") && !pathname.startsWith("/documents/upload"));
  return pathname === href || pathname.startsWith(`${href}/`);
}

async function signOut() {
  await fetch("/api/auth/logout", { method: "POST" });
  // A full navigation discards the client router cache of authenticated pages.
  window.location.replace("/login");
}

function Brand({ compactable = false }: { compactable?: boolean }) {
  return (
    <Link href="/dashboard" className="flex min-w-0 items-center gap-2.5 rounded-md focus-visible:ring-2 focus-visible:ring-ring">
      <span aria-hidden className="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-gradient-to-br from-primary to-hybrid text-[11px] font-bold tracking-tight text-primary-foreground shadow-sm">
        OT
      </span>
      <span className={cn("min-w-0 leading-tight", compactable && "sidebar-label")}>
        <span className="block truncate text-sm font-semibold tracking-tight">OmniTrust Ledger</span>
        <span className="block truncate text-[11px] text-muted-foreground">PKI document signing</span>
      </span>
    </Link>
  );
}

function NavList({ pathname, onNavigate, compactable = false }: { pathname: string; onNavigate?: () => void; compactable?: boolean }) {
  return (
    <nav aria-label="Main" className="space-y-5">
      {NAVIGATION.map((group) => (
        <div key={group.label}>
          <div className={cn("mb-1.5 px-2.5 text-[10px] font-semibold uppercase tracking-[0.08em] text-muted-foreground/80", compactable && "sidebar-label")}>{group.label}</div>
          <ul className="space-y-0.5">
            {group.items.map((item) => {
              const active = isActive(pathname, item.href);
              const Icon = item.icon;
              return (
                <li key={item.href}>
                  <Link
                    href={item.href}
                    onClick={onNavigate}
                    aria-current={active ? "page" : undefined}
                    title={item.label}
                    className={cn(
                      "sidebar-link group relative flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-sm transition-colors focus-visible:ring-2 focus-visible:ring-ring",
                      active ? "bg-card font-medium text-foreground shadow-card ring-1 ring-border" : "text-sidebar-foreground hover:bg-card/70 hover:text-foreground",
                    )}
                  >
                    {active && <span aria-hidden className="absolute inset-y-1.5 left-0 w-0.5 rounded-full bg-primary" />}
                    <Icon aria-hidden className={cn("h-4 w-4 shrink-0", active ? "text-primary" : "text-muted-foreground group-hover:text-foreground")} />
                    <span className={cn("truncate", compactable && "sidebar-label")}>{item.label}</span>
                  </Link>
                </li>
              );
            })}
          </ul>
        </div>
      ))}
    </nav>
  );
}

function Breadcrumbs({ pathname }: { pathname: string }) {
  const segments = pathname.split("/").filter(Boolean);
  return (
    <nav aria-label="Breadcrumb" className="min-w-0">
      <ol className="flex min-w-0 items-center gap-1 text-sm">
        {segments.map((segment, index) => {
          const href = `/${segments.slice(0, index + 1).join("/")}`;
          const label = SEGMENT_LABELS[segment] ?? (segment.length > 12 ? `…${segment.slice(-6)}` : segment);
          const last = index === segments.length - 1;
          return (
            <li key={href} className="flex min-w-0 items-center gap-1">
              {index > 0 && <ChevronRight aria-hidden className="h-3.5 w-3.5 shrink-0 text-muted-foreground/60" />}
              {last ? (
                <span aria-current="page" className="truncate font-medium text-foreground" title={segment}>
                  {label}
                </span>
              ) : (
                <Link href={href} className="truncate text-muted-foreground hover:text-foreground" title={segment}>
                  {label}
                </Link>
              )}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}

type PaletteEntry = { id: string; label: string; description: string; group: string; icon: LucideIcon; run: () => void };

function CommandPalette({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const router = useRouter();
  const [query, setQuery] = useState("");
  const [cursor, setCursor] = useState(0);
  const listRef = useRef<HTMLUListElement>(null);

  const entries = useMemo<PaletteEntry[]>(
    () => [
      ...NAVIGATION.flatMap((group) =>
        group.items.map((item) => ({ id: item.href, label: item.label, description: item.description, group: group.label, icon: item.icon, run: () => router.push(item.href) })),
      ),
      {
        id: "theme",
        label: "Switch theme",
        description: "Cycle light, dark and system",
        group: "Actions",
        icon: PanelLeftOpen,
        run: () => {
          const order = ["light", "dark", "system"] as const;
          applyTheme(order[(order.indexOf(readThemePreference()) + 1) % order.length]);
        },
      },
      { id: "sign-out", label: "Sign out", description: "End this session", group: "Actions", icon: LogOut, run: () => void signOut() },
    ],
    [router],
  );

  const matches = useMemo(() => {
    const terms = query.toLowerCase().split(/\s+/).filter(Boolean);
    return entries.filter((entry) => terms.every((term) => `${entry.label} ${entry.description} ${entry.group}`.toLowerCase().includes(term)));
  }, [entries, query]);

  useEffect(() => {
    if (open) {
      setQuery("");
      setCursor(0);
    }
  }, [open]);

  useEffect(() => {
    setCursor(0);
  }, [query]);

  useEffect(() => {
    listRef.current?.querySelector<HTMLElement>(`[data-index="${cursor}"]`)?.scrollIntoView({ block: "nearest" });
  }, [cursor]);

  const choose = (entry: PaletteEntry | undefined) => {
    if (!entry) return;
    onOpenChange(false);
    entry.run();
  };

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-background/60 backdrop-blur-sm data-[state=open]:animate-fade-in" />
        <Dialog.Content
          className="fixed left-1/2 top-[14vh] z-50 w-[min(38rem,calc(100vw-2rem))] -translate-x-1/2 overflow-hidden rounded-xl border bg-popover text-popover-foreground shadow-elevated data-[state=open]:animate-scale-in"
          onKeyDown={(event) => {
            if (event.key === "ArrowDown") {
              event.preventDefault();
              setCursor((value) => Math.min(value + 1, Math.max(matches.length - 1, 0)));
            } else if (event.key === "ArrowUp") {
              event.preventDefault();
              setCursor((value) => Math.max(value - 1, 0));
            } else if (event.key === "Enter") {
              event.preventDefault();
              choose(matches[cursor]);
            }
          }}
        >
          <Dialog.Title className="sr-only">Command palette</Dialog.Title>
          <Dialog.Description className="sr-only">Search pages and actions, then press Enter.</Dialog.Description>
          <div className="flex items-center gap-2 border-b px-3">
            <Search aria-hidden className="h-4 w-4 text-muted-foreground" />
            <input
              autoFocus
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search pages and actions…"
              aria-label="Search pages and actions"
              className="h-12 w-full bg-transparent text-sm outline-none placeholder:text-muted-foreground"
            />
            <kbd className="hidden rounded border bg-muted px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground sm:block">Esc</kbd>
          </div>
          <ul ref={listRef} role="listbox" aria-label="Results" className="max-h-[50vh] overflow-y-auto p-2">
            {matches.length === 0 && <li className="px-3 py-8 text-center text-sm text-muted-foreground">No pages or actions match “{query}”.</li>}
            {matches.map((entry, index) => {
              const Icon = entry.icon;
              const selected = index === cursor;
              return (
                <li key={entry.id} data-index={index} role="option" aria-selected={selected}>
                  <button
                    type="button"
                    onMouseMove={() => setCursor(index)}
                    onClick={() => choose(entry)}
                    className={cn("flex w-full items-center gap-3 rounded-lg px-3 py-2 text-left", selected ? "bg-accent text-accent-foreground" : "text-foreground")}
                  >
                    <span className={cn("grid h-8 w-8 shrink-0 place-items-center rounded-md border bg-card", selected && "border-primary/30")}>
                      <Icon aria-hidden className="h-4 w-4" />
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-sm font-medium">{entry.label}</span>
                      <span className="block truncate text-xs text-muted-foreground">{entry.description}</span>
                    </span>
                    <span className="hidden text-[10px] uppercase tracking-wide text-muted-foreground sm:block">{entry.group}</span>
                    {selected && <CornerDownLeft aria-hidden className="h-3.5 w-3.5 text-muted-foreground" />}
                  </button>
                </li>
              );
            })}
          </ul>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

export function AppShell({ user, children }: { user: { email: string; role: string }; children: React.ReactNode }) {
  const pathname = usePathname();
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);

  const toggleSidebar = useCallback(() => {
    const root = document.documentElement;
    const collapsed = root.getAttribute("data-sidebar") !== "collapsed";
    if (collapsed) root.setAttribute("data-sidebar", "collapsed");
    else root.removeAttribute("data-sidebar");
    try {
      localStorage.setItem(SIDEBAR_STORAGE_KEY, collapsed ? "collapsed" : "expanded");
    } catch {
      // Collapse still applies for this page when storage is unavailable.
    }
  }, []);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setPaletteOpen((value) => !value);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const initials = user.email.slice(0, 2).toUpperCase();

  return (
    <div className="flex min-h-screen bg-background">
      <aside className="app-sidebar sticky top-0 hidden h-screen w-64 shrink-0 flex-col border-r border-sidebar-border bg-sidebar transition-[width] duration-200 lg:flex">
        <div className="flex h-14 items-center justify-between gap-2 px-3">
          <Brand compactable />
          <button
            type="button"
            onClick={toggleSidebar}
            aria-label="Collapse or expand the sidebar"
            title="Collapse or expand the sidebar"
            className="sidebar-label grid h-7 w-7 shrink-0 place-items-center rounded-md text-muted-foreground hover:bg-card hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring"
          >
            <PanelLeftClose aria-hidden className="h-4 w-4" />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto px-3 py-4">
          <NavList pathname={pathname} compactable />
        </div>
        <div className="space-y-2 border-t border-sidebar-border p-3">
          <button
            type="button"
            onClick={toggleSidebar}
            aria-label="Expand the sidebar"
            title="Expand the sidebar"
            className="sidebar-expand hidden h-8 w-full place-items-center rounded-md text-muted-foreground hover:bg-card hover:text-foreground"
          >
            <PanelLeftOpen aria-hidden className="h-4 w-4" />
          </button>
          <div className="sidebar-label rounded-lg border border-warning/25 bg-warning/5 px-2.5 py-2 text-[11px] leading-snug text-muted-foreground">
            <span className="font-semibold text-warning">Demo build.</span> Local CA and local key storage; not for production use.
          </div>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-40 flex h-14 items-center gap-3 border-b bg-background/80 px-4 backdrop-blur supports-[backdrop-filter]:bg-background/70 sm:px-6">
          <Dialog.Root open={mobileOpen} onOpenChange={setMobileOpen}>
            <Dialog.Trigger asChild>
              <button type="button" aria-label="Open navigation" className="grid h-8 w-8 place-items-center rounded-md border bg-card text-muted-foreground hover:text-foreground lg:hidden">
                <Menu aria-hidden className="h-4 w-4" />
              </button>
            </Dialog.Trigger>
            <Dialog.Portal>
              <Dialog.Overlay className="fixed inset-0 z-50 bg-background/60 backdrop-blur-sm data-[state=open]:animate-fade-in" />
              <Dialog.Content className="fixed inset-y-0 left-0 z-50 flex w-72 max-w-[85vw] flex-col border-r bg-sidebar shadow-elevated data-[state=open]:animate-slide-up">
                <Dialog.Title className="sr-only">Navigation</Dialog.Title>
                <Dialog.Description className="sr-only">Pages of OmniTrust Ledger</Dialog.Description>
                <div className="flex h-14 items-center justify-between px-3">
                  <Brand />
                  <Dialog.Close aria-label="Close navigation" className="grid h-8 w-8 place-items-center rounded-md text-muted-foreground hover:text-foreground">
                    <X aria-hidden className="h-4 w-4" />
                  </Dialog.Close>
                </div>
                <div className="flex-1 overflow-y-auto px-3 py-4">
                  <NavList pathname={pathname} onNavigate={() => setMobileOpen(false)} />
                </div>
              </Dialog.Content>
            </Dialog.Portal>
          </Dialog.Root>

          <Breadcrumbs pathname={pathname} />

          <div className="ml-auto flex items-center gap-2">
            <button
              type="button"
              onClick={() => setPaletteOpen(true)}
              className="group hidden h-8 items-center gap-2 rounded-lg border bg-card px-2.5 text-sm text-muted-foreground shadow-card transition-colors hover:text-foreground md:flex"
            >
              <Search aria-hidden className="h-3.5 w-3.5" />
              <span className="pr-6">Search…</span>
              <kbd className="rounded border bg-muted px-1.5 py-px font-mono text-[10px]">Ctrl K</kbd>
            </button>
            <button type="button" onClick={() => setPaletteOpen(true)} aria-label="Search pages and actions" className="grid h-8 w-8 place-items-center rounded-md border bg-card text-muted-foreground md:hidden">
              <Search aria-hidden className="h-4 w-4" />
            </button>
            <ThemeToggle className="hidden sm:inline-flex" />
            <div className="flex items-center gap-2 rounded-lg border bg-card py-1 pl-1 pr-1.5 shadow-card">
              <span aria-hidden className="grid h-6 w-6 place-items-center rounded-md bg-accent text-[10px] font-semibold text-accent-foreground">
                {initials}
              </span>
              <span className="hidden min-w-0 leading-tight md:block">
                <span className="block max-w-[10rem] truncate text-xs font-medium">{user.email}</span>
                <span className="block text-[10px] uppercase tracking-wide text-muted-foreground">{user.role}</span>
              </span>
              <button
                type="button"
                onClick={() => void signOut()}
                className="ml-1 inline-flex h-6 items-center gap-1 rounded-md px-1.5 text-xs text-muted-foreground hover:bg-secondary hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring"
              >
                <LogOut aria-hidden className="h-3.5 w-3.5" />
                <span>Sign out</span>
              </button>
            </div>
          </div>
        </header>

        <main id="main" className="mx-auto w-full max-w-7xl flex-1 animate-fade-in px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
          {children}
        </main>
        <footer className="border-t px-4 py-3 sm:px-6 lg:px-8">
          <DemoNotice className="mx-auto max-w-7xl" />
        </footer>
      </div>

      <CommandPalette open={paletteOpen} onOpenChange={setPaletteOpen} />
    </div>
  );
}
