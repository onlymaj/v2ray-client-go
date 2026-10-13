import { useState } from 'preact/hooks';
import { Plus, RefreshCw, Trash2, Upload } from 'lucide-react';
import { api } from '../api.js';
import { useApi, Loading, PageHead, Field, Alert, Empty, useAction, toast, confirmDialog } from '../components/common.jsx';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { Card, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { Input } from '../components/ui/input';
import { Textarea } from '../components/ui/textarea';
import { fmtAgo } from '../util.js';
import { unencrypted, UNENCRYPTED_HINT } from './Clients.jsx';

export function Import() {
  const [text, setText] = useState('');
  const [result, setResult] = useState(null);
  const [busy, run] = useAction();
  const [subs, subsErr, reloadSubs, setSubs] = useApi('/subscriptions');
  const [sub, setSub] = useState({ name: '', url: '' });
  const [refreshing, setRefreshing] = useState({});

  const doImport = async (e) => {
    e.preventDefault();
    const r = await run(() => api('/import', { method: 'POST', body: { text } }));
    if (!r) return;
    setResult(r);
    if (r.added.length && !r.errors.length) setText('');
    toast(`Added ${r.added.length} client${r.added.length === 1 ? '' : 's'}`, r.errors.length && !r.added.length ? 'err' : 'ok');
  };

  const addSub = async (e) => {
    e.preventDefault();
    if (await run(() => api('/subscriptions', { method: 'POST', body: sub }), 'Subscription added')) {
      setSub({ name: '', url: '' });
      reloadSubs();
    }
  };

  const refresh = async (s) => {
    setRefreshing((x) => ({ ...x, [s.id]: true }));
    try {
      const u = await api(`/subscriptions/${s.id}/refresh`, { method: 'POST' });
      setSubs((xs) => xs.map((x) => (x.id === s.id ? u : x)));
      toast(u.lastError ? `Refresh failed: ${u.lastError}` : `${u.name}: ${u.count} clients${u.note ? `. ${u.note}` : ''}`, u.lastError ? 'err' : 'ok');
    } catch (err) {
      toast(err.message, 'err');
    }
    setRefreshing((x) => ({ ...x, [s.id]: false }));
  };

  const remove = async (s) => {
    const ok = await confirmDialog({
      title: `Remove ${s.name}?`,
      description: `The ${s.count} client${s.count === 1 ? '' : 's'} imported from this subscription are deleted too, with the rules that target them.`,
      confirm: 'Remove',
      destructive: true,
    });
    if (ok && (await run(() => api(`/subscriptions/${s.id}`, { method: 'DELETE' }), 'Subscription removed'))) reloadSubs();
  };

  return (
    <>
      <PageHead title="Import clients" back="#/clients" />
      <Card>
        <form onSubmit={doImport} className="flex flex-col gap-4">
          <CardHeader className="flex-col items-start gap-1">
            <CardTitle>Paste share links</CardTitle>
            <CardDescription>One <code>vless://</code> or <code>vmess://</code> link per line. A base64 subscription body also works.</CardDescription>
          </CardHeader>
          <Textarea rows={7} className="font-mono text-xs" spellCheck={false} placeholder="vless://uuid@host:443?security=reality&...#name" value={text} onInput={(e) => setText(e.currentTarget.value)} />
          <div className="flex justify-end">
            <Button type="submit" disabled={busy || !text.trim()}><Upload />Import</Button>
          </div>
        </form>
        {result && (
          <div className="flex flex-col gap-2 text-[13px]">
            <p className="m-0">
              <b>{result.added.length}</b> added, <b>{result.skipped}</b> skipped (already present),{' '}
              <b className={result.errors.length ? 'text-destructive' : ''}>{result.errors.length}</b> failed.
            </p>
            {result.added.length > 0 && (
              <p className="m-0 text-muted-foreground">New clients are enabled and join the first-start (Default) group, if it still exists. Remove them there if they should not carry its traffic.</p>
            )}
            {result.added.length > 0 && (
              <div className="flex flex-wrap gap-x-3 gap-y-1">
                {result.added.map((c) => (
                  <span key={c.id} className="inline-flex items-center gap-1">
                    <a href={`#/clients/${c.id}`} className="underline">{c.name}</a>
                    {unencrypted(c) && <Badge variant="destructive" title={UNENCRYPTED_HINT}>unencrypted</Badge>}
                  </span>
                ))}
              </div>
            )}
            {result.errors.map((e, i) => (
              <Alert key={i} variant="destructive">
                {e.line ? `Line ${e.line}: ` : ''}{e.error}
                <div className="truncate font-mono text-xs opacity-80">{e.text}</div>
              </Alert>
            ))}
          </div>
        )}
      </Card>

      <Card>
        <CardHeader><CardTitle>Subscriptions</CardTitle></CardHeader>
        {!subs ? <Loading error={subsErr} /> : subs.length === 0 ? <Empty>No subscriptions.</Empty> : (
          <ul className="m-0 list-none divide-y p-0">
            {subs.map((s) => (
              <li key={s.id} className="flex flex-wrap items-center gap-3 py-3 first:pt-0">
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium">{s.name}</span>
                    <Badge>{s.count} clients</Badge>
                  </div>
                  <div className="truncate font-mono text-xs text-muted-foreground">{s.url}</div>
                  <div className="text-xs text-muted-foreground">Updated {fmtAgo(s.lastUpdate)}</div>
                  {s.lastError && <div className="text-xs text-destructive">{s.lastError}</div>}
                  {s.note && <div className="text-xs text-muted-foreground">{s.note}</div>}
                </div>
                <div className="flex gap-1">
                  <Button variant="outline" size="sm" onClick={() => refresh(s)} disabled={refreshing[s.id]}>
                    <RefreshCw className={refreshing[s.id] ? 'animate-spin' : ''} />
                    {refreshing[s.id] ? 'Refreshing' : 'Refresh'}
                  </Button>
                  <Button variant="ghost" size="icon-sm" className="text-destructive" onClick={() => remove(s)} aria-label={`Remove ${s.name}`}><Trash2 /></Button>
                </div>
              </li>
            ))}
          </ul>
        )}
        <form onSubmit={addSub} className="grid gap-4 border-t pt-4 sm:grid-cols-[1fr_2fr_auto] sm:items-end">
          <Field label="Name"><Input value={sub.name} placeholder="optional" onInput={(e) => setSub({ ...sub, name: e.currentTarget.value })} /></Field>
          <Field label="Subscription URL">
            <Input type="url" required value={sub.url} placeholder="https://..." onInput={(e) => setSub({ ...sub, url: e.currentTarget.value })} />
          </Field>
          <Button type="submit" disabled={busy}><Plus />Add subscription</Button>
        </form>
      </Card>
    </>
  );
}
