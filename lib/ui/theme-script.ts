// Runs inline in <head>, before first paint, so the page never flashes the wrong theme or sidebar
// width. Kept outside any "use client" module: a server layout importing a plain value from a client
// module receives a reference, not the value. The Content-Security-Policy already allows inline
// scripts (lib/http/security-headers.ts), so this adds no new weakening.

export const THEME_STORAGE_KEY = "omnitrust-theme";
export const SIDEBAR_STORAGE_KEY = "omnitrust-sidebar";

export const themeBootstrapScript = `(function(){try{var root=document.documentElement;var preference=localStorage.getItem("${THEME_STORAGE_KEY}")||"system";var dark=preference==="dark"||(preference==="system"&&window.matchMedia("(prefers-color-scheme: dark)").matches);root.classList.toggle("dark",dark);if(localStorage.getItem("${SIDEBAR_STORAGE_KEY}")==="collapsed"){root.setAttribute("data-sidebar","collapsed");}}catch(error){}})();`;
