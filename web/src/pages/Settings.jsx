import { useEffect, useState } from 'preact/hooks';
import { Save } from 'lucide-react';
import { api } from '../api.js';
import { Field, SimpleSelect, Loading, PageHead, useAction } from '../components/common.jsx';
import { Button } from '../components/ui/button';
import { Card, CardAction, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { Input } from '../components/ui/input';
import { Switch } from '../components/ui/switch';

const PORTS = [
  ['transparent', 'Transparent proxy', 'Port that LAN traffic is redirected to. Takes effect after restart', 1],
  ['socks', 'SOCKS5', '0 disables. Takes effect after restart', 0],
  ['http', 'HTTP proxy', '0 disables. Takes effect after restart', 0],
  ['dns', 'DNS', '0 disables. Takes effect after restart', 0],
  ['ui', 'Web UI', 'Takes effect after restart', 1],
];
const grid = 'grid grid-cols-[repeat(auto-fill,minmax(min(100%,200px),1fr))] gap-4';

export function Settings() {
  const [s, setS] = useState(null);
  const [err, setErr] = useState(null);
  const [busy, run] = useAction();

  const [saved, setSaved] = useState(null); // routeros url and user as stored on the server
  const load = (v) => {
    setS(v);
    setSaved({ url: v.routeros.url, user: v.routeros.user });
  };

  useEffect(() => {
    api('/settings').then(load, (e) => setErr(e.message));
  }, []);
  if (!s) return <Loading error={err} />;

  const port = (k) => (e) => setS({ ...s, ports: { ...s.ports, [k]: e.currentTarget.value } });
  const ros = (k, v) => setS({ ...s, routeros: { ...s.routeros, [k]: v } });

  const save = async (e) => {
    e.preventDefault();
    const ports = Object.fromEntries(Object.entries(s.ports).map(([k, v]) => [k, Number(v)]));
    const { passwordSet, ...routeros } = s.routeros;
    const body = { ...s, ports, healthInterval: Number(s.healthInterval), routeros };
    const out = await run(() => api('/settings', { method: 'PUT', body }), 'Settings saved');
    if (out) load(out);
  };

  // The server clears the stored password when the URL or user changes, so
  // that it is never sent to a different host or account.
  const rosMoved = s.routeros.url !== saved.url || s.routeros.user !== saved.user;

  return (
    <form onSubmit={save} className="flex flex-col gap-6">
      <PageHead title="Settings">
        <Button type="submit" disabled={busy}><Save />{busy ? 'Saving...' : 'Save'}</Button>
      </PageHead>

      <Card>
        <CardHeader><CardTitle>Ports</CardTitle></CardHeader>
        <div className={grid}>
          {PORTS.map(([k, label, hint, min]) => (
            <Field key={k} label={label} hint={hint}>
              <Input type="number" min={min} max="65535" required value={s.ports[k]} onInput={port(k)} />
            </Field>
          ))}
        </div>
      </Card>

      <Card>
        <CardHeader><CardTitle>Health checks and DNS</CardTitle></CardHeader>
        <div className={grid}>
          <Field label="Check URL" hint="Should return HTTP 204" wide>
            <Input type="url" required value={s.healthUrl} onInput={(e) => setS({ ...s, healthUrl: e.currentTarget.value })} />
          </Field>
          <Field label="Interval (seconds)">
            <Input type="number" min="5" max="3600" required value={s.healthInterval} onInput={(e) => setS({ ...s, healthInterval: e.currentTarget.value })} />
          </Field>
          <Field label="Kill switch" hint="When the chosen group has no healthy member, or the chosen client is disabled. A rule to one enabled client never falls back: its connections fail while it is down.">
            <SimpleSelect value={s.killSwitch} options={[['block', 'Block traffic'], ['direct', 'Send direct']]} onChange={(v) => setS({ ...s, killSwitch: v })} />
          </Field>
          <Field label="DNS upstream" hint="ip:port, queried over TCP through the matched client">
            <Input
              required
              className="font-mono text-xs"
              placeholder="1.1.1.1:53"
              pattern="^(\d{1,3}(\.\d{1,3}){3}|\[[0-9a-fA-F:]+\]):\d{1,5}$"
              title="IP and port, e.g. 1.1.1.1:53 or [2606:4700::1111]:53"
              value={s.dnsUpstream ?? ''}
              onInput={(e) => setS({ ...s, dnsUpstream: e.currentTarget.value })}
            />
          </Field>
        </div>
      </Card>

      <Card>
        <CardHeader className="items-start">
          <div className="flex flex-col gap-1">
            <CardTitle>Allow untrusted servers on private/LAN addresses</CardTitle>
            <CardDescription>
              Off by default. When on, untrusted clients (from a subscription or imported links) may use private and
              CGNAT server addresses, so a malicious link can make the container connect to devices on your LAN.
              Clients you add or save in the editor may always use them.
            </CardDescription>
          </div>
          <CardAction>
            <Switch
              checked={!!s.allowPrivateServers}
              onCheckedChange={(v) => setS({ ...s, allowPrivateServers: v })}
              aria-label="Allow untrusted servers on private/LAN addresses"
            />
          </CardAction>
        </CardHeader>
      </Card>

      <Card>
        <CardHeader className="items-start">
          <div className="flex flex-col gap-1">
            <CardTitle>RouterOS API</CardTitle>
            <CardDescription>Keeps an address list of proxy server IPs on the router so their traffic bypasses the container.</CardDescription>
          </div>
          <CardAction>
            <Switch checked={s.routeros.enabled} onCheckedChange={(v) => ros('enabled', v)} aria-label="Enable RouterOS integration" />
          </CardAction>
        </CardHeader>
        <fieldset className={grid + ' m-0 min-w-0 border-0 p-0 disabled:opacity-55'} disabled={!s.routeros.enabled}>
          <Field label="URL" hint="e.g. https://172.17.0.1 (REST API)">
            <Input type="url" value={s.routeros.url} onInput={(e) => ros('url', e.currentTarget.value)} required={s.routeros.enabled} />
          </Field>
          <Field label="User">
            <Input value={s.routeros.user} autoComplete="off" onInput={(e) => ros('user', e.currentTarget.value)} required={s.routeros.enabled} />
          </Field>
          <Field label="Password" hint={!s.routeros.passwordSet ? '' : rosMoved ? 'URL or user changed: the stored password is cleared on save. Enter it again' : 'Leave empty to keep the current password'}>
            <Input
              type="password"
              autoComplete="new-password"
              value={s.routeros.password || ''}
              placeholder={s.routeros.passwordSet && !rosMoved ? '(unchanged)' : ''}
              onInput={(e) => ros('password', e.currentTarget.value)}
            />
          </Field>
          <Field label="Certificate SHA-256" hint="Pins the router's HTTPS certificate (64 hex characters). Empty: not verified">
            <Input
              className="font-mono text-xs"
              autoComplete="off"
              pattern="^\s*([0-9a-fA-F]{2}[: ]?){31}[0-9a-fA-F]{2}\s*$"
              title="SHA-256 fingerprint: 64 hex characters"
              value={s.routeros.certSha256 || ''}
              onInput={(e) => ros('certSha256', e.currentTarget.value)}
            />
          </Field>
          <Field label="Address list">
            <Input value={s.routeros.addressList} onInput={(e) => ros('addressList', e.currentTarget.value)} required={s.routeros.enabled} />
          </Field>
        </fieldset>
      </Card>
    </form>
  );
}
