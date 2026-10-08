import { useCallback, useState } from 'preact/hooks';
import { ArrowDown, ArrowUp, Pencil, Plus, Trash2, X } from 'lucide-react';
import { api } from '../api.js';
import { live, useLiveEvents, useLiveTick } from '../live.js';
import { useApi, StatusDot, Field, SimpleSelect, Loading, PageHead, Empty, SectionHeading, useAction, confirmDialog } from '../components/common.jsx';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { Card, CardAction, CardHeader, CardTitle } from '../components/ui/card';
import { Input } from '../components/ui/input';
import { Switch } from '../components/ui/switch';
import { cn } from '../lib/utils';
import { fmtRate, fmtMs } from '../util.js';
import { useClientStatus } from './Clients.jsx';

const STRATEGIES = [
  ['failover', 'Failover (first healthy member)'],
  ['least-ping', 'Least ping'],
  ['round-robin', 'Round robin'],
  ['sticky', 'Sticky (per source)'],
];

function GroupForm({ group, clients, onDone }) {
  const [g, setG] = useState(group);
  const [busy, run] = useAction();
  const byId = Object.fromEntries(clients.map((c) => [c.id, c]));
  const available = clients.filter((c) => !g.members.includes(c.id));

  const move = (i, d) => {
    const m = [...g.members];
    [m[i], m[i + d]] = [m[i + d], m[i]];
    setG({ ...g, members: m });
  };
  const save = async (e) => {
    e.preventDefault();
    const body = { name: g.name, strategy: g.strategy, members: g.members, stickyIncludeDest: g.stickyIncludeDest };
    const ok = await run(() => (g.id ? api(`/groups/${g.id}`, { method: 'PUT', body }) : api('/groups', { method: 'POST', body })), 'Group saved');
    if (ok) onDone(true);
  };

  return (
    <Card className="border-border-strong">
      <form onSubmit={save} className="flex flex-col gap-4">
        <CardHeader><CardTitle>{g.id ? `Edit ${group.name}` : 'New group'}</CardTitle></CardHeader>
        <div className="grid grid-cols-[repeat(auto-fill,minmax(min(100%,220px),1fr))] gap-4">
          <Field label="Name"><Input required value={g.name} onInput={(e) => setG({ ...g, name: e.currentTarget.value })} /></Field>
          <Field label="Strategy"><SimpleSelect value={g.strategy} options={STRATEGIES} onChange={(v) => setG({ ...g, strategy: v })} /></Field>
          {g.strategy === 'sticky' && (
            <Field label="Include destination" hint="Pin per source + destination instead of per source only">
              <div className="flex h-9 items-center">
                <Switch checked={g.stickyIncludeDest} onCheckedChange={(v) => setG({ ...g, stickyIncludeDest: v })} aria-label="Include destination" />
              </div>
            </Field>
          )}
        </div>
        <SectionHeading>Members {g.strategy === 'failover' && '(tried in this order)'}</SectionHeading>
        <ol className="m-0 flex list-none flex-col gap-1.5 p-0">
          {g.members.map((id, i) => (
            <li key={id} className="flex min-w-0 items-center gap-1 rounded-md border bg-background py-1 pl-3 pr-1">
              <span className="w-5 shrink-0 text-xs text-muted-foreground">{i + 1}</span>
              <span className="flex min-w-0 flex-1 items-center gap-2 text-[13px]">
                <StatusDot state={byId[id]?.status.state} />
                <span className="truncate">{byId[id]?.name || id}</span>
              </span>
              <Button type="button" variant="ghost" size="icon-sm" disabled={i === 0} onClick={() => move(i, -1)} aria-label="Move up"><ArrowUp /></Button>
              <Button type="button" variant="ghost" size="icon-sm" disabled={i === g.members.length - 1} onClick={() => move(i, 1)} aria-label="Move down"><ArrowDown /></Button>
              <Button type="button" variant="ghost" size="icon-sm" className="text-destructive" onClick={() => setG({ ...g, members: g.members.filter((x) => x !== id) })} aria-label="Remove"><X /></Button>
            </li>
          ))}
          {g.members.length === 0 && <li className="text-[13px] text-muted-foreground">No members yet.</li>}
        </ol>
        {available.length > 0 && (
          <SimpleSelect
            key={g.members.length}
            value=""
            placeholder="+ Add member..."
            options={available.map((c) => [c.id, c.name])}
            onChange={(v) => setG({ ...g, members: [...g.members, v] })}
          />
        )}
        <div className="flex justify-end gap-2">
          <Button type="button" variant="ghost" onClick={() => onDone(false)}>Cancel</Button>
          <Button type="submit" disabled={busy}>Save</Button>
        </div>
      </form>
    </Card>
  );
}

export function Groups() {
  useLiveTick('traffic');
  const [groups, err, reload, setGroups] = useApi('/groups');
  const [clients, , , setClients] = useApi('/clients');
  const [editing, setEditing] = useState(null);
  const [, run] = useAction();
  useClientStatus(setClients);
  useLiveEvents(
    useCallback((type, d) => {
      if (type === 'group') setGroups((gs) => gs && gs.map((g) => (g.id === d.id ? { ...g, current: d.current } : g)));
    }, []),
  );

  if (!groups || !clients) return <Loading error={err} />;
  const byId = Object.fromEntries(clients.map((c) => [c.id, c]));
  const rate = (g) => g.members.reduce((a, id) => [a[0] + (live.clients[id]?.downRate || 0), a[1] + (live.clients[id]?.upRate || 0)], [0, 0]);

  const del = async (g) => {
    const ok = await confirmDialog({ title: `Delete ${g.name}?`, confirm: 'Delete', destructive: true });
    if (ok && (await run(() => api(`/groups/${g.id}`, { method: 'DELETE' }), 'Group deleted'))) reload();
  };
  const done = (changed) => {
    setEditing(null);
    if (changed) reload();
  };

  return (
    <>
      <PageHead title="Groups" subtitle="Fail over or balance across several clients.">
        {!editing && (
          <Button onClick={() => setEditing({ name: '', strategy: 'failover', members: [], stickyIncludeDest: false })}><Plus />New group</Button>
        )}
      </PageHead>
      {editing && <GroupForm key={editing.id || 'new'} group={editing} clients={clients} onDone={done} />}
      {groups.length === 0 && !editing && <Card><Empty>No groups. Groups let rules fail over or balance across clients.</Empty></Card>}
      <div className="grid gap-6 lg:grid-cols-2">
        {groups.map((g) => {
          const cur = byId[g.current];
          const [down, up] = rate(g);
          return (
            <Card key={g.id}>
              <CardHeader>
                <CardTitle>
                  {g.name}
                  <Badge>{g.strategy}</Badge>
                  {g.strategy === 'sticky' && g.stickyIncludeDest && <Badge variant="info">+dest</Badge>}
                </CardTitle>
                <CardAction>
                  <Button variant="ghost" size="icon-sm" onClick={() => setEditing(g)} aria-label={`Edit ${g.name}`}><Pencil /></Button>
                  <Button variant="ghost" size="icon-sm" className="text-destructive" onClick={() => del(g)} aria-label={`Delete ${g.name}`}><Trash2 /></Button>
                </CardAction>
              </CardHeader>
              <p className="m-0 text-[13px]">
                <span className="text-muted-foreground">Current: </span>
                {cur ? <a href={`#/clients/${cur.id}`} className="font-medium">{cur.name}</a> : <span className="text-destructive">no healthy member</span>}
                <span className="text-muted-foreground"> · </span>
                <span className="text-success">↓{fmtRate(down)}</span> <span className="text-warning">↑{fmtRate(up)}</span>
              </p>
              <ol className="m-0 flex list-none flex-col gap-1.5 p-0">
                {g.members.map((id, i) => {
                  const c = byId[id];
                  return (
                    <li
                      key={id}
                      className={cn('flex min-w-0 items-center gap-2 rounded-md border px-3 py-1.5 text-[13px]', id === g.current && 'border-success/50 bg-success/8')}
                    >
                      <span className="w-4 shrink-0 text-xs text-muted-foreground">{i + 1}</span>
                      <StatusDot state={c?.enabled ? c.status.state : 'disabled'} />
                      <span className="min-w-0 flex-1 truncate">{c?.name || id}</span>
                      <span className="text-xs text-muted-foreground tabular-nums">{c?.status.state === 'up' ? fmtMs(c.status.delayMs) : c?.status.state}</span>
                    </li>
                  );
                })}
              </ol>
            </Card>
          );
        })}
      </div>
    </>
  );
}
