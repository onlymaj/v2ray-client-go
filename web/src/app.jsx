import { useEffect, useState } from 'preact/hooks';
import { Activity, Layers, LayoutDashboard, ListOrdered, LogOut, Menu, Server, Settings as SettingsIcon } from 'lucide-react';
import { api, setUnauthorizedHandler } from './api.js';
import { live, startLive, stopLive, useLiveTick } from './live.js';
import { ConfirmHost, Toasts, toast } from './components/common.jsx';
import { ThemeToggle } from './components/ThemeToggle.jsx';
import { Button } from './components/ui/button';
import { Sheet, SheetContent, SheetDescription, SheetTitle } from './components/ui/sheet';
import { cn } from './lib/utils';
import { navigate } from './util.js';
import { Login } from './pages/Login.jsx';
import { Dashboard } from './pages/Dashboard.jsx';
import { Clients } from './pages/Clients.jsx';
import { ClientEdit } from './pages/ClientEdit.jsx';
import { ClientDetail } from './pages/ClientDetail.jsx';
import { Import } from './pages/Import.jsx';
import { Groups } from './pages/Groups.jsx';
import { Rules } from './pages/Rules.jsx';
import { Connections } from './pages/Connections.jsx';
import { Settings } from './pages/Settings.jsx';

// Hash routes, first match wins. Named groups are passed as props.
const routes = [
  [/^\/$/, Dashboard],
  [/^\/clients$/, Clients],
  [/^\/clients\/new$/, ClientEdit],
  [/^\/clients\/import$/, Import],
  [/^\/clients\/(?<id>[^/]+)\/edit$/, ClientEdit],
  [/^\/clients\/(?<id>[^/]+)$/, ClientDetail],
  [/^\/groups$/, Groups],
  [/^\/rules$/, Rules],
  [/^\/connections$/, Connections],
  [/^\/settings$/, Settings],
];

const nav = [
  ['/', 'Dashboard', LayoutDashboard],
  ['/clients', 'Clients', Server],
  ['/groups', 'Groups', Layers],
  ['/rules', 'Rules', ListOrdered],
  ['/connections', 'Connections', Activity],
  ['/settings', 'Settings', SettingsIcon],
];

const currentPath = () => decodeURI(location.hash.slice(1)) || '/';

function useHashPath() {
  const [path, setPath] = useState(currentPath);
  useEffect(() => {
    const on = () => setPath(currentPath());
    addEventListener('hashchange', on);
    return () => removeEventListener('hashchange', on);
  }, []);
  return path;
}

function LiveBadge() {
  useLiveTick('conn');
  return (
    <span
      className="inline-flex items-center gap-2 text-[11px] font-medium uppercase tracking-[0.06em] text-muted-foreground"
      title={live.connected ? 'Live updates connected' : 'Live updates disconnected'}
    >
      <span className={cn('size-2 rounded-full', live.connected ? 'bg-success shadow-[0_0_0_3px] shadow-success/20' : 'bg-muted-foreground')} />
      <span className="max-sm:sr-only">{live.connected ? 'Live' : 'Offline'}</span>
    </span>
  );
}

function Brand() {
  return (
    <a href="#/" className="flex min-w-0 items-center gap-2.5 text-foreground hover:no-underline">
      <span className="grid size-8 shrink-0 place-items-center rounded-full border bg-primary text-sm font-bold text-primary-foreground shadow-sm">V</span>
      <span className="truncate text-[15px] font-semibold">v2ray-client-go</span>
    </a>
  );
}

function NavLinks({ section, onLogout }) {
  return (
    <nav className="flex min-h-0 flex-1 flex-col gap-0.5 overflow-y-auto p-3">
      {nav.map(([href, label, Icon]) => (
        <a
          key={href}
          href={'#' + href}
          className={cn(
            'flex items-center gap-3 rounded-md px-3 py-2 text-sm text-muted-foreground transition-colors hover:bg-accent hover:text-foreground hover:no-underline',
            section === href && 'bg-accent font-medium text-foreground',
          )}
        >
          <Icon className="size-4" />
          {label}
        </a>
      ))}
      <button
        onClick={onLogout}
        className="mt-auto flex cursor-pointer items-center gap-3 rounded-md px-3 py-2 text-left text-sm text-muted-foreground hover:bg-accent hover:text-foreground"
      >
        <LogOut className="size-4" />
        Log out
      </button>
    </nav>
  );
}

export function App() {
  const path = useHashPath();
  const [authed, setAuthed] = useState(null);
  const [menu, setMenu] = useState(false);

  useEffect(() => {
    setUnauthorizedHandler(() => {
      stopLive();
      setAuthed(false);
    });
    api('/me').then(
      () => (setAuthed(true), startLive()),
      () => setAuthed(false),
    );
  }, []);
  useEffect(() => setMenu(false), [path]);

  if (authed === null) return <div className="p-6 text-center text-sm text-muted-foreground">Loading...</div>;
  if (!authed)
    return (
      <>
        <Login onLogin={() => (setAuthed(true), startLive(), path === '/login' && navigate('/'))} />
        <Toasts />
      </>
    );

  let Page = null;
  let params = {};
  for (const [re, C] of routes) {
    const m = path.match(re);
    if (m) {
      Page = C;
      params = m.groups || {};
      break;
    }
  }
  const section = '/' + (path.split('/')[1] || '');

  const logout = async () => {
    try {
      await api('/logout', { method: 'POST' });
    } catch (err) {
      // The request may never have reached the server: the session and its
      // cookie would live on behind a login page that looks signed out.
      if (err.status !== 401) {
        toast('Logout failed, you are still signed in', 'err');
        return;
      }
    }
    stopLive();
    setAuthed(false);
  };

  return (
    <div className="flex min-h-screen">
      <aside className="sticky top-0 z-30 hidden h-dvh w-60 shrink-0 flex-col border-r bg-card lg:flex">
        <div className="flex h-16 shrink-0 items-center border-b px-5"><Brand /></div>
        <NavLinks section={section} onLogout={logout} />
      </aside>

      <Sheet open={menu} onOpenChange={setMenu}>
        <SheetContent side="left" className="gap-0 p-0">
          <SheetTitle className="flex h-16 items-center border-b px-5"><Brand /></SheetTitle>
          <SheetDescription className="sr-only">Navigation</SheetDescription>
          <NavLinks section={section} onLogout={logout} />
        </SheetContent>
      </Sheet>

      <div className="min-w-0 flex-1">
        <header className="sticky top-0 z-20 flex h-16 items-center gap-3 border-b bg-card px-4 sm:px-8">
          <Button variant="ghost" size="icon-sm" className="-ml-1.5 lg:hidden" aria-label="Open menu" onClick={() => setMenu(true)}>
            <Menu className="size-5" />
          </Button>
          <div className="min-w-0 flex-1 lg:hidden"><Brand /></div>
          <div className="ml-auto flex items-center gap-3">
            <LiveBadge />
            <ThemeToggle />
          </div>
        </header>
        <main className="mx-auto flex w-full max-w-[1280px] min-w-0 flex-col gap-6 px-4 pb-12 pt-6 sm:px-8">
          {Page ? <Page key={path} {...params} /> : <div className="p-6 text-center text-muted-foreground">Page not found. <a href="#/">Go to dashboard</a></div>}
        </main>
      </div>
      <Toasts />
      <ConfirmHost />
    </div>
  );
}
